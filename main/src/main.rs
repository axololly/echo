use std::time::Duration;

use backoffice::interval;
use rootcause::{Report, Result, bail};

async fn error_handler(err: Report) {
    println!("encountered error with my_task: {err:?}");
}

#[interval(secs = 1)]
#[on_error(error_handler)]
async fn my_task() -> Result<()> {
    println!("my_task was run!");

    bail!("this is to test error handling");
}

#[tokio::main]
async fn main() {
    my_task.start();

    println!("started running task");

    tokio::time::sleep(Duration::from_secs(3)).await;

    my_task.stop();
}
