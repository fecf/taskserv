use serde::Deserialize;
use serde_with::formats::*;
use serde_with::*;
use std::collections::HashMap;

pub const CONFIG_FILE_NAME: &str = "taskserv.conf";

#[derive(Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "snake_case")]
pub enum When {
    Trigger,
    Startup,
    Cron(String),
}

#[serde_as]
#[derive(Default, Deserialize, Debug, PartialEq, Clone)]
pub struct Task {
    #[serde_as(deserialize_as = "OneOrMany<_, PreferMany>")]
    pub when: Vec<When>,
    pub path: String,
    pub cwd: Option<String>,
    pub args: Option<Vec<String>>,
    pub detached: Option<bool>,
    pub max_instances: Option<i32>,
}

#[derive(Default, Deserialize, Debug)]
pub struct Config {
    pub dry_run: Option<bool>,
    #[serde(flatten)]
    pub tasks: HashMap<String, Task>,
}
