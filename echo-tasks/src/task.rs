use std::{sync::{Arc, Mutex}, time::Duration};

use async_trait::async_trait;
use tokio::{sync::{SetOnce, mpsc}, task::JoinHandle, time::interval};

#[async_trait]
pub trait Task: Send + Sync {
    /// How long to wait between running the task.
    fn interval(&self) -> Duration;

    /// The main callback for the task.
    async fn callback(&self, running_task: RunningTask);
}

fn run_task(task: Arc<dyn Task>, running_task: RunningTask) -> RunningTaskInfo {
    let (stopper, mut receiver) = mpsc::channel::<()>(1);

    let once_cell = SetOnce::const_new();
    let once_cell2 = once_cell.clone();

    let mut interval = interval(task.interval());

    let handle = tokio::spawn(async move {
        interval.tick().await;

        loop {
            task.callback(running_task.clone()).await;

            tokio::select! {
                Some(_) = receiver.recv() => {
                    let _ = once_cell2.set(());

                    break
                },
                _ = interval.tick() => {}
            };
        }
    });

    RunningTaskInfo {
        handle,
        stopper,
        stopped: once_cell
    }
}

struct RunningTaskInfo {
    handle: JoinHandle<()>,
    stopper: mpsc::Sender<()>,
    stopped: SetOnce<()>
}

#[derive(Clone)]
pub struct RunningTask {
    task: Arc<dyn Task>,
    info: Arc<Mutex<Option<RunningTaskInfo>>>
}

impl RunningTask {
    /// Create a new [`RunningTask`] from the given [`Task`].
    ///
    /// This does not start running the task.
    pub fn new(task: impl Task + 'static) -> Self {
        Self {
            task: Arc::new(task),
            info: Arc::new(Mutex::new(None))
        }
    }

    /// Start running the task.
    pub fn start(&self) {
        self.info.clear_poison();

        let info = self.info.lock().unwrap();

        if info.is_some() {
            return;
        }

        drop(info);

        let new_info = run_task(self.task.clone(), self.clone());

        self.info.clear_poison();

        let mut info = self.info.lock().unwrap();

        *info = Some(new_info);
    }

    /// Stop running the task.
    ///
    /// This allows the task to finish its current cycle
    /// before stopping the loop.
    pub fn stop(&self) {
        self.info.clear_poison();

        let info = self.info.lock().unwrap();

        let Some(RunningTaskInfo { stopper, stopped, .. }) = &*info else {
            return;
        };

        let stopper = stopper.clone();
        let stopped = stopped.clone();

        let info = self.info.clone();

        tokio::spawn(async move {
            let _ = stopper.send(()).await;

            stopped.wait().await;

            info.clear_poison();

            let mut info = info.lock().unwrap();

            *info = None;
        });
    }

    /// Wait until the task has stopped successfully.
    pub async fn wait_until_stopped(&self) {
        self.info.clear_poison();

        let cell = {
            let info = self.info.lock().unwrap();

            let Some(RunningTaskInfo { stopped, .. }) = &*info else {
                return;
            };

            stopped.clone()
        };

        cell.wait().await;
    }

    /// Cancel the internal task.
    pub fn cancel(&self) {
        self.info.clear_poison();

        let mut info = self.info.lock().unwrap();

        let Some(RunningTaskInfo { handle, .. }) = &*info else {
            return;
        };

        handle.abort();

        *info = None;
    }

    /// Restart the internal task by cancelling then restarting.
    pub fn restart(&self) {
        self.cancel();

        self.start();
    }

    /// Restart the internal task, waiting for it to gracefully
    /// stop before starting the task again.
    ///
    /// This will block until the task finishes.
    pub async fn restart_graceful(&self) {
        self.stop();

        self.wait_until_stopped().await;

        self.start();
    }
}
