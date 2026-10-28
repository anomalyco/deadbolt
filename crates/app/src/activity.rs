//! Settings' Activity: what callers asked the agent for, and what this app
//! showed or copied, newest first, as the agent recorded it. Never values.
//! The app tells the agent about its own reveals and copies, which the agent
//! can't see.

use deadbolt_client::Paths;
use deadbolt_client::protocol::{ActivityEntry, AppAction, Command, Outcome, Reply};
use rune::{El, ScrollSpec, Transition, Tx, col, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Kit};

use crate::agent::{Done, Failure, Job};
use crate::model::App;

/// How many of the newest entries Settings shows.
const SHOWN: u32 = 50;

#[derive(Default)]
pub struct Activity {
    pub open: bool,
    pub loading: bool,
    pub entries: Vec<ActivityEntry>,
    pub error: Option<String>,
    /// The list asked for: a reply to an earlier ask is dropped.
    seq: u64,
}

impl Activity {
    /// Closes the list, and drops the reply to an ask on its way.
    pub(crate) fn forget(&mut self) {
        self.seq += 1;
        *self = Activity {
            seq: self.seq,
            ..Activity::default()
        };
    }
}

impl App {
    pub fn toggle_activity(&mut self) {
        if self.activity.open {
            self.activity.forget();
        } else {
            self.activity.open = true;
            self.load_activity();
        }
    }

    fn load_activity(&mut self) {
        self.activity.seq += 1;
        self.activity.loading = true;
        self.agent.send(Job::Activity {
            seq: self.activity.seq,
        });
    }

    /// The agent recorded something: an open list asks again.
    pub(crate) fn on_activity_changed(&mut self) {
        if self.activity.open {
            self.load_activity();
        }
    }

    pub(crate) fn on_activity(
        &mut self,
        seq: u64,
        result: Result<Vec<ActivityEntry>, Failure>,
        tx: &mut Tx,
    ) {
        if !self.activity.open || seq != self.activity.seq {
            return;
        }
        self.activity.loading = false;
        match result {
            Ok(entries) => {
                self.activity.entries = entries;
                self.activity.error = None;
            }
            Err(failure) if failure.locked() => {
                self.activity.forget();
                self.on_locked(tx);
            }
            Err(failure) => self.activity.error = Some(failure.message),
        }
    }

    /// Tells the agent this app showed or copied `field` of the shown item.
    pub(crate) fn report(&self, action: AppAction, field: &str) {
        let Some(item) = &self.detail else { return };
        self.report_item(action, &item.id, &item.label, field);
    }

    /// Tells the agent this app showed or copied `field` of the item `id`.
    pub(crate) fn report_item(&self, action: AppAction, id: &str, title: &str, field: &str) {
        self.agent.send(Job::Report {
            action,
            item: id.into(),
            title: title.into(),
            field: field.into(),
        });
    }
}

pub(crate) async fn run(paths: &Paths, job: Job) -> Done {
    match job {
        Job::Activity { seq } => {
            let command = Command::ActivityList {
                since: None,
                limit: Some(SHOWN),
                before: None,
            };
            let result = match deadbolt_client::simple(paths, command).await {
                Ok(Reply::Activity { entries }) => Ok(entries),
                Ok(_) => Err(Failure {
                    code: None,
                    message: "unexpected reply from the agent".into(),
                }),
                Err(error) => Err(error.into()),
            };
            Done::Activity { seq, result }
        }
        Job::Report {
            action,
            item,
            title,
            field,
        } => {
            let command = Command::ActivityReport {
                action,
                vault: None,
                item,
                title,
                field,
            };
            // A report the agent missed (locked, gone) isn't the user's problem.
            drop(deadbolt_client::simple(paths, command).await);
            Done::Reported
        }
        _ => Done::Reported,
    }
}

/// "2m ago  OpenCode › zsh › deadbolt  item-get GitHub (password)".
fn line(entry: &ActivityEntry, now: u64) -> String {
    let age = now.saturating_sub(entry.time);
    let ago = match age {
        0..60 => "now".to_string(),
        60..3600 => format!("{}m ago", age / 60),
        3600..86400 => format!("{}h ago", age / 3600),
        _ => format!("{}d ago", age / 86400),
    };
    let mut what = entry.command.clone();
    let items: Vec<&str> = entry.items.iter().map(|i| i.title.as_str()).collect();
    if !items.is_empty() {
        what.push(' ');
        what.push_str(&items.join(", "));
    }
    if !entry.fields.is_empty() {
        what.push_str(&format!(" ({})", entry.fields.join(", ")));
    }
    match entry.outcome {
        Outcome::Allowed => {}
        Outcome::Locked => what.push_str(", locked"),
        Outcome::Failed => what.push_str(", failed"),
    }
    if entry.more > 0 {
        what.push_str(&format!(", {} more", entry.more));
    }
    format!("{ago} · {} · {what}", entry.caller.label)
}

#[expect(
    clippy::disallowed_methods,
    reason = "wall clock for how long ago an entry was"
)]
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Settings' row: the button, then the newest entries.
pub fn setting(s: &App, k: &Kit) -> El {
    let a = &s.activity;
    let section = col().key("activity").w(240.0).gap(6.0).child(
        text("Activity")
            .key("activity-label")
            .font(k.ty.text_small)
            .color(k.c.text_muted),
    );
    let section = section.child(
        Button::new(if a.open {
            "Hide activity"
        } else {
            "Show activity"
        })
        .variant(ButtonVariant::Ghost)
        .control_size(ControlSize::Regular)
        .on_press(|s: &mut App| s.toggle_activity())
        .build(k)
        .key("activity-button"),
    );
    if !a.open {
        return section;
    }
    if let Some(error) = &a.error {
        return section.child(
            text(error.clone())
                .key("activity-error")
                .font(k.ty.small_medium)
                .color(k.c.danger.fg)
                .wrap()
                .w_full(),
        );
    }
    if a.entries.is_empty() {
        let empty = if a.loading {
            "Loading…"
        } else {
            "Nothing yet"
        };
        return section.child(
            text(empty)
                .key("activity-empty")
                .font(k.ty.text_small)
                .color(k.c.text_muted),
        );
    }
    let now = now();
    let rows = a.entries.iter().map(|entry| {
        text(line(entry, now))
            .key(format!("activity-{}", entry.id))
            .font(k.ty.text_small)
            .color(k.c.text_base)
            .wrap()
            .w_full()
    });
    section.child(
        col()
            .key("activity-list")
            .w_full()
            .max_h(220.0)
            .gap(6.0)
            .scroll(ScrollSpec {
                stick_bottom: false,
            })
            .children(rows)
            .transition(Transition::opacity()),
    )
}

#[cfg(test)]
mod tests {
    use deadbolt_client::protocol::{ActivityItem, CallerInfo, Tier};

    use super::*;

    #[test]
    fn a_line_says_who_did_what_to_which_field() {
        let entry = ActivityEntry {
            id: 3,
            time: 1_000,
            caller: CallerInfo::unverified("OpenCode › zsh › deadbolt"),
            tier: Tier::Read,
            command: "item-get".into(),
            items: vec![ActivityItem {
                vault: None,
                id: Some("i1".into()),
                title: "GitHub".into(),
            }],
            fields: vec!["password".into()],
            outcome: Outcome::Allowed,
            more: 0,
        };
        assert_eq!(
            line(&entry, 1_120),
            "2m ago · OpenCode › zsh › deadbolt · item-get GitHub (password)"
        );
        let folded = ActivityEntry {
            command: "more-past-limit".into(),
            items: Vec::new(),
            fields: Vec::new(),
            more: 25,
            ..entry
        };
        assert_eq!(
            line(&folded, 1_120),
            "2m ago · OpenCode › zsh › deadbolt · more-past-limit, 25 more"
        );
    }
}
