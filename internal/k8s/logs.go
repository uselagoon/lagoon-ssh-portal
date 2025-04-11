package k8s

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

var (
	// defaultTailLines is the number of log lines to tail by default if no number
	// is specified
	defaultTailLines int64 = 32
	// maxTailLines is the maximum number of log lines to tail
	maxTailLines int64 = 1024
	// limitBytes defines the maximum number of bytes of logs returned from a
	// single container
	limitBytes int64 = 1 * 1024 * 1024 // 1MiB

	// ErrConcurrentLogLimit indicates that the maximum number of concurrent log
	// sessions has been reached.
	ErrConcurrentLogLimit = errors.New("reached concurrent log limit")
	// ErrLogTimeLimit indicates that the maximum log session time has been
	// exceeded.
	ErrLogTimeLimit = errors.New("exceeded maximum log session time")
)

// linewiseCopy reads strings separated by \n from logStream, and writes them
// with the given prefix and \n stripped to the logs channel. It returns when
// ctx is cancelled or the logStream closes.
func linewiseCopy(
	ctx context.Context,
	prefix string,
	logs chan<- string,
	logStream io.ReadCloser,
) {
	s := bufio.NewScanner(logStream)
	for s.Scan() {
		select {
		case logs <- fmt.Sprintf("%s %s", prefix, s.Text()):
		case <-ctx.Done():
			return
		}
	}
}

// readLogs reads logs from the given pod, writing them back to the logs
// channel in a linewise manner. A goroutine is started via egSend to tail logs
// for each container. requestID is used to de-duplicate simultaneous logs
// requests associated with a single call to the higher-level Logs() function.
//
// readLogs returns immediately, and relies on ctx cancellation to ensure the
// goroutines it starts are cleaned up.
func (c *Client) readLogs(ctx context.Context, requestID string,
	egSend *errgroup.Group, p *corev1.Pod, containerName string, follow bool,
	tailLines int64, logs chan<- string) error {
	var cStatuses []corev1.ContainerStatus
	// if containerName is not specified, send logs for all containers
	if containerName == "" {
		cStatuses = p.Status.ContainerStatuses
	} else {
		for _, cStatus := range p.Status.ContainerStatuses {
			if containerName == cStatus.Name {
				cStatuses = append(cStatuses, cStatus)
				break
			}
		}
		if len(cStatuses) == 0 {
			return fmt.Errorf("couldn't find container: %s", containerName)
		}
	}
	for _, cStatus := range cStatuses {
		// skip setting up another log stream if container is already being logged
		_, exists := c.logStreamIDs.LoadOrStore(requestID+cStatus.ContainerID, true)
		if exists {
			continue
		}
		// set up stream for a single container
		req := c.clientset.CoreV1().Pods(p.Namespace).GetLogs(p.Name,
			&corev1.PodLogOptions{
				Container:  cStatus.Name,
				Follow:     follow,
				Timestamps: true,
				TailLines:  &tailLines,
				LimitBytes: &limitBytes,
			})
		logStream, err := req.Stream(ctx)
		if err != nil {
			return fmt.Errorf("couldn't stream logs: %v", err)
		}
		egSend.Go(func() error {
			defer c.logStreamIDs.Delete(cStatus.ContainerID)
			defer logStream.Close()
			linewiseCopy(ctx, fmt.Sprintf("[pod/%s/%s]", p.Name, cStatus.Name), logs,
				logStream)
			// When a pod is terminating, the k8s API sometimes sends an event
			// showing a healthy pod _after_ an existing logStream for the same pod
			// has closed. This happens occasionally on scale-down of a deployment.
			// When this occurs there is a race where linewiseCopy() returns, then
			// the "healthy" event comes in and linewiseCopy() is called again, only
			// to return immediately. This can result in duplicated log lines being
			// returned on the logs channel.
			// To hack around this behaviour, pause here before exiting. This means
			// that the container ID is retained in c.logStreamIDs for a brief period
			// after logs stop streaming, which causes "healthy pod" events from the
			// k8s API to be ignored for that period and thereby avoiding duplicate
			// log lines being returned to the caller.
			time.Sleep(time.Second)
			return nil
		})
	}
	return nil
}

// podEventHandler receives pod objects from the podInformer and, if they are
// in a ready state, starts streaming logs from them.
func (c *Client) podEventHandler(ctx context.Context,
	cancel context.CancelFunc, requestID string, egSend *errgroup.Group,
	container string, follow bool, tailLines int64, logs chan<- string, obj any) {
	// panic if obj is not a pod, since we specifically use a pod informer
	pod := obj.(*corev1.Pod)
	if !slices.ContainsFunc(pod.Status.Conditions,
		func(cond corev1.PodCondition) bool {
			return cond.Type == corev1.ContainersReady &&
				cond.Status == corev1.ConditionTrue
		}) {
		return // pod not ready
	}
	egSend.Go(func() error {
		readLogsErr := c.readLogs(ctx, requestID, egSend, pod, container, follow,
			tailLines, logs)
		if readLogsErr != nil {
			cancel()
			return fmt.Errorf("couldn't read logs on new pod: %v", readLogsErr)
		}
		return nil
	})
}

// newPodInformer sets up a k8s informer on pods in the given deployment, and
// returns the informer in an inert state. The informer is configured with
// event handlers to read logs from pods in the deployment, writing log lines
// back to the logs channel. It transparently handles the deployment scaling up
// and down (e.g. pods being added / deleted / restarted).
//
// When the caller calls Run() on the returned informer, it will start watching
// for events and sending to the logs channel.
func (c *Client) newPodInformer(ctx context.Context,
	cancel context.CancelFunc, requestID string, egSend *errgroup.Group,
	namespace, deployment, container string, follow bool, tailLines int64,
	logs chan<- string) (cache.SharedIndexInformer, error) {
	// get the deployment
	d, err := c.clientset.AppsV1().Deployments(namespace).Get(ctx, deployment,
		metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("couldn't get deployment: %v", err)
	}
	// configure the informer factory, filtering on deployment selector labels
	factory := informers.NewSharedInformerFactoryWithOptions(
		c.clientset,
		time.Hour,
		informers.WithNamespace(namespace),
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.LabelSelector =
				labels.SelectorFromSet(d.Spec.Selector.MatchLabels).String()
		}),
	)
	// construct the informer
	podInformer := factory.Core().V1().Pods().Informer()
	_, err = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		// AddFunc handles events for new and existing pods. Since new pods are not
		// in a ready state when initially added, it doesn't start log streaming
		// for those.
		AddFunc: func(obj any) {
			c.podEventHandler(ctx, cancel, requestID, egSend, container, follow,
				tailLines, logs, obj)
		},
		// UpdateFunc handles events for pod state changes. When new pods are added
		// (e.g. deployment is scaled up) it repeatedly receives events until the
		// pod is in its final healthy state. For that reason, the
		// podEventHandler() inspects the pod state before initiating log
		// streaming.
		UpdateFunc: func(_, obj any) {
			c.podEventHandler(ctx, cancel, requestID, egSend, container, follow,
				tailLines, logs, obj)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("couldn't add event handlers to informer: %v", err)
	}
	return podInformer, nil
}

// Logs takes a target namespace, deployment, and stdio stream, and writes the
// log output of the pods of of the deployment to the stdio stream. If
// container is specified, only logs of this container within the deployment
// are returned.
//
// This function exits on one of the following events:
//
//  1. It finishes sending the logs of the pods. This only occurs if
//     follow=false.
//  2. ctx is cancelled (signalling that the SSH channel was closed).
//  3. An unrecoverable error occurs.
//
// If a call to Logs would exceed the configured maximum number of concurrent
// log sessions, ErrConcurrentLogLimit is returned.
//
// If the configured log time limit is exceeded, ErrLogTimeLimit is returned.
func (c *Client) Logs(
	ctx context.Context,
	namespace,
	deployment,
	container string,
	follow bool,
	tailLines int64,
	stdio io.ReadWriter,
) error {
	// Exit with an error if we have hit the concurrent log limit.
	if !c.logSem.TryAcquire(1) {
		return ErrConcurrentLogLimit
	}
	defer c.logSem.Release(1)
	// Wrap the context so we can cancel subroutines of this function on error.
	childCtx, cancel := context.WithTimeout(ctx, c.logTimeLimit)
	defer cancel()
	// Generate a requestID value to uniquely distinguish between multiple calls
	// to this function. This requestID is used in readLogs() to distinguish
	// entries in c.logStreamIDs.
	requestID := uuid.New().String()
	// clamp tailLines
	if tailLines < 1 {
		tailLines = defaultTailLines
	}
	if tailLines > maxTailLines {
		tailLines = maxTailLines
	}
	// put sending goroutines in an errgroup.Group to handle errors, and
	// receiving goroutines in a waitgroup (since they have no errors)
	var egSend errgroup.Group
	var wgRecv sync.WaitGroup
	// initialise a buffered channel for the worker goroutines to write to, and
	// for this function to read log lines from
	logs := make(chan string, 4)
	// start a goroutine reading from the logs channel and writing back to stdio
	wgRecv.Add(1)
	go func() {
		defer wgRecv.Done()
		for {
			select {
			case msg := <-logs:
				// ignore errors writing to stdio. this may happen if the client
				// disconnects after reading off the channel but before the log can be
				// written. there's nothing we can do in this case and we'll select
				// ctx.Done() shortly anyway.
				_, _ = fmt.Fprintln(stdio, msg)
			case <-childCtx.Done():
				return // context done - client went away or error within Logs()
			}
		}
	}()
	if follow {
		// If following the logs, start a goroutine which watches for new (and
		// existing) pods in the deployment and starts streaming logs from them.
		egSend.Go(func() error {
			podInformer, err := c.newPodInformer(childCtx, cancel, requestID,
				&egSend, namespace, deployment, container, follow, tailLines, logs)
			if err != nil {
				return fmt.Errorf("couldn't construct new pod informer: %v", err)
			}
			podInformer.Run(childCtx.Done())
			if errors.Is(childCtx.Err(), context.DeadlineExceeded) {
				return ErrLogTimeLimit
			}
			return nil
		})
	} else {
		// If not following the logs, avoid constructing an informer. Instead just
		// read the logs from all existing pods.
		d, err := c.clientset.AppsV1().Deployments(namespace).Get(childCtx,
			deployment, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("couldn't get deployment: %v", err)
		}
		pods, err := c.clientset.CoreV1().Pods(namespace).List(childCtx,
			metav1.ListOptions{
				LabelSelector: labels.FormatLabels(d.Spec.Selector.MatchLabels),
			})
		if err != nil {
			return fmt.Errorf("couldn't get pods: %v", err)
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("no pods for deployment %s", deployment)
		}
		for _, pod := range pods.Items {
			egSend.Go(func() error {
				readLogsErr := c.readLogs(childCtx, requestID, &egSend, &pod,
					container, follow, tailLines, logs)
				if readLogsErr != nil {
					return fmt.Errorf("couldn't read logs on existing pods: %v", readLogsErr)
				}
				if errors.Is(childCtx.Err(), context.DeadlineExceeded) {
					return ErrLogTimeLimit
				}
				return nil
			})
		}
	}
	// Wait for the writes to finish, then close the logs channel, wait for the
	// read goroutine to exit, and return any sendErr.
	sendErr := egSend.Wait()
	cancel()
	wgRecv.Wait()
	return sendErr
}
