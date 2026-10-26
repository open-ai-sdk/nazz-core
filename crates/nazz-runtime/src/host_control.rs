//! Opt-in trusted host placement; selection alone does not authorize launch.
//!
//! Configuration and eligibility observations must come from the authenticated
//! host controller, never a task/tool payload. Observations have no intrinsic
//! freshness authority. The storage lease remains the takeover authority;
//! absence from presence/heartbeat is not proof an old process has stopped.

use std::time::Duration;

use nazz_core::{ActorGrant, AttemptId};
use nazz_storage::{ExecutionStore, StorageError as StoreError};
use thiserror::Error;

/// Trusted configuration order, independent of task parameters.
pub struct HostPolicy<'a> {
    pub preferred: &'a str,
    pub fallbacks: &'a [&'a str],
}

/// A trusted controller's observation, not a self-reported worker permission.
pub struct HostEligibility<'a> {
    pub host: &'a str,
    pub online: bool,
    pub eligible: bool,
}

#[derive(Debug, Error)]
pub enum HostControlError {
    #[error("host policy contains empty or duplicate identities")]
    InvalidConfiguration,
    #[error("host eligibility snapshot is incomplete or ambiguous")]
    InvalidSnapshot,
    #[error("no configured host is online and eligible")]
    NoEligibleHost,
    #[error("requesting worker is not the selected host")]
    NotSelected,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl HostPolicy<'_> {
    /// Preferred first, then the configured fallback order. Require exactly one
    /// observation for every configured identity; never infer missing liveness.
    pub fn select<'a>(
        &'a self,
        observed: &[HostEligibility<'_>],
    ) -> Result<&'a str, HostControlError> {
        let mut hosts = std::iter::once(self.preferred).chain(self.fallbacks.iter().copied());
        for (index, host) in hosts.clone().enumerate() {
            if host.trim().is_empty() || hosts.clone().take(index).any(|prior| prior == host) {
                return Err(HostControlError::InvalidConfiguration);
            }
        }
        for (index, item) in observed.iter().enumerate() {
            if !hosts.clone().any(|host| host == item.host)
                || observed[..index]
                    .iter()
                    .any(|prior| prior.host == item.host)
            {
                return Err(HostControlError::InvalidSnapshot);
            }
        }
        if observed.len() != self.fallbacks.len() + 1 {
            return Err(HostControlError::InvalidSnapshot);
        }
        hosts
            .find(|host| {
                observed
                    .iter()
                    .any(|item| item.host == *host && item.online && item.eligible)
            })
            .ok_or(HostControlError::NoEligibleHost)
    }

    /// Route before claiming the SAME durable attempt. The selected host is the
    /// lease holder, so a caller cannot route to B and acquire A's identity.
    /// Store enforces live-lease exclusion, monotonic generation and unknown
    /// effect hold. This does not poll, launch, renew automatically or stop old
    /// processes; each effect/publication still needs the existing store guards.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keep execution authority and checkpoint inputs explicit."
    )]
    pub async fn claim(
        &self,
        observed: &[HostEligibility<'_>],
        requesting_host: &str,
        store: &impl ExecutionStore,
        grant: &ActorGrant,
        attempt: &AttemptId,
        generation: u64,
        ttl: Duration,
    ) -> Result<(), HostControlError> {
        if self.select(observed)? != requesting_host {
            return Err(HostControlError::NotSelected);
        }
        store
            .claim_lease(grant, attempt, generation, requesting_host, ttl)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(host: &str, online: bool, eligible: bool) -> HostEligibility<'_> {
        HostEligibility {
            host,
            online,
            eligible,
        }
    }

    #[test]
    fn preference_and_fallback_order_ignore_observation_order() {
        let policy = HostPolicy {
            preferred: "a",
            fallbacks: &["b", "c"],
        };
        let mut snapshot = [
            observation("c", true, true),
            observation("b", true, true),
            observation("a", true, true),
        ];
        assert_eq!(policy.select(&snapshot).unwrap(), "a");
        snapshot[2].online = false;
        assert_eq!(policy.select(&snapshot).unwrap(), "b");
        snapshot[1].eligible = false;
        assert_eq!(policy.select(&snapshot).unwrap(), "c");
    }

    #[test]
    fn unavailable_or_ineligible_hosts_cannot_be_selected() {
        let policy = HostPolicy {
            preferred: "a",
            fallbacks: &["b"],
        };
        assert!(matches!(
            policy.select(&[observation("a", false, true), observation("b", true, false)]),
            Err(HostControlError::NoEligibleHost)
        ));
    }

    #[test]
    fn missing_duplicate_or_unconfigured_observations_are_denied() {
        let policy = HostPolicy {
            preferred: "a",
            fallbacks: &["b"],
        };
        for snapshot in [
            vec![observation("a", true, true)],
            vec![observation("a", true, true), observation("a", true, true)],
            vec![
                observation("a", true, true),
                observation("other", true, true),
            ],
        ] {
            assert!(matches!(
                policy.select(&snapshot),
                Err(HostControlError::InvalidSnapshot)
            ));
        }
    }

    #[test]
    fn empty_or_duplicate_configuration_is_denied() {
        for policy in [
            HostPolicy {
                preferred: "",
                fallbacks: &["b"],
            },
            HostPolicy {
                preferred: "a",
                fallbacks: &["a"],
            },
            HostPolicy {
                preferred: "a",
                fallbacks: &["b", "b"],
            },
        ] {
            assert!(matches!(
                policy.select(&[]),
                Err(HostControlError::InvalidConfiguration)
            ));
        }
    }
}
