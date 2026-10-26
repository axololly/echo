use std::{sync::{Arc, Mutex}, time::Duration};

use async_trait::async_trait;
use tokio::{sync::mpsc::{Sender, channel}, task::JoinHandle, time::interval};

#[async_trait]
pub trait Task<C>: Send + Sync {
    /// How long to wait between running the task.
    fn interval(&self) -> Duration;

    /// The main callback for the task.
    async fn callback(&self, ctx: C);
}

fn run_task<C>(
    task: Arc<dyn Task<C>>,
    make_context_fn: impl Fn() ->
) -> RunningTaskInfo {
    let (sender, mut receiver) = channel::<()>(1);

    let mut interval = interval(task.interval());

    let handle = tokio::spawn(async move {
        interval.tick().await;

        loop {
            task.callback().await;

            tokio::select! {
                val = receiver.recv() => {
                    if val.is_some() {
                        break;
                    }
                },
                _ = interval.tick() => {}
            };
        }
    });

    RunningTaskInfo {
        handle,
        stopper: sender
    }
}

struct RunningTaskInfo {
    handle: JoinHandle<()>,
    stopper: Sender<()>
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

        let mut info = self.info.lock().unwrap();

        if info.is_some() {
            return;
        }

        *info = Some(run_task(self.task.clone()));
    }

    /// Stop running the task.
    ///
    /// This allows the task to finish its current cycle
    /// before stopping the loop.
    pub fn stop(&self) {
        self.info.clear_poison();

        let info = self.info.lock().unwrap();

        let Some(RunningTaskInfo { stopper, .. }) = &*info else {
            return;
        };

        let stopper = stopper.clone();
        let info = self.info.clone();

        tokio::spawn(async move {
            let _ = stopper.send(()).await;

            info.clear_poison();

            let mut info = info.lock().unwrap();

            *info = None;
        });
    }

    /// Cancel the internal task.
    pub fn cancel(&self) {
        self.info.clear_poison();

        let info = self.info.lock().unwrap();

        let Some(RunningTaskInfo { handle, .. }) = &*info else {
            return;
        };

        handle.abort();
    }
}
