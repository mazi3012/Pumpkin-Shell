# Escape corpus

The escape corpus is the list of attacks that the sandbox must stop or
report. Each row is one attack and the test that runs it inside a real
sandbox. The results are reported as N/N on a named corpus version. Run it
with `scripts/escape-corpus.sh`.

Corpus version: **v1** (first release, Linux, Kiro).

Families (PRD section 7 and `.kiro/steering/tech.md`): FS (filesystem), NET
(network), IPC (inter-process channels), PROC (processes), ENV (environment),
REG (registry), WS (workspace integrity), EXEC (program starts), SBX (the
sandbox itself).

Each row's test is a Rust test in `crates/pks-cli/tests/sandbox.rs`. The test
name is in backticks in the last column. The runner reads the table, so keep
the layout: the ID in the first column and the test name in the last.

| ID | Family | Attack | Expected | Test |
|---|---|---|---|---|
| FS-01 | FS | Read the real host home directory | Not visible | `corpus_fs_01_the_host_home_directory_is_not_visible` |
| FS-02 | FS | Write to `/usr` and `/etc` | Refused (read-only, permission) | `corpus_fs_02_writes_to_the_system_are_refused` |
| FS-03 | FS | Write to `/var` and `/root` | Refused | `corpus_fs_03_writes_outside_the_repo_and_ide_home_are_refused` |
| FS-04 | FS | Rename a protected file in the repo (`.envrc`) | Staged, not applied | `protected_paths_are_staged_and_cannot_be_renamed` |
| FS-05 | FS | Delete a protected path | The repo is unchanged | `deleting_a_protected_path_never_touches_the_repo` |
| FS-06 | FS | Read a decoy credential | Seen on the host (HIGH) | `a_read_of_a_decoy_inside_the_sandbox_is_seen_on_the_host` |
| FS-07 | FS | Copy or hard-link a decoy and read the copy | Still seen on the host | `copying_or_hard_linking_a_decoy_is_still_seen` |
| FS-08 | FS | Write, then read, outside the Landlock write paths | Only the write paths accept writes | `landlock_allows_writes_under_rw_and_refuses_everywhere_else` |
| WS-01 | WS | Enable `chat.tools.autoApprove` in the repo | Staged, CRITICAL, paused | `scenario_3_enabling_auto_approve_is_staged_and_critical` |
| WS-02 | WS | Create a new command hook | Staged, CRITICAL | `scenario_4_a_new_command_hook_is_staged_and_critical` |
| WS-03 | WS | Edit a watched file | Held for review; the repo is unchanged | `an_edit_to_a_watched_file_is_held_and_the_repo_is_unchanged` |
| WS-04 | WS | Write a secret into the repo | Reported without its value | `a_secret_written_in_the_sandbox_is_reported_without_its_value` |
| WS-05 | WS | Delete more than 50 files | Found and restorable | `a_mass_delete_inside_the_sandbox_is_found_and_restored` |
| NET-01 | NET | Connect straight to `1.1.1.1` (no proxy) | Refused | `corpus_net_01_a_direct_internet_connection_is_refused` |
| NET-02 | NET | Connect straight to the metadata address `169.254.169.254` | Refused | `corpus_net_02_the_cloud_metadata_address_is_unreachable` |
| NET-03 | NET | Resolve a name without the proxy | Fails | `corpus_net_03_direct_name_resolution_fails` |
| NET-04 | NET | Connect straight to `registry.npmjs.org` and `pypi.org` | Refused; the mirror is the only route | `corpus_net_04_a_registry_cannot_be_reached_directly` |
| NET-05 | NET | Connect to a host port that is not listed | Refused (NET-DIRECT-CONNECT) | `a_listed_host_port_reaches_the_host_service_and_an_unlisted_one_does_not` |
| NET-06 | NET | Connect to a host port that is not listed, from a program | Reported with the `host_ports` hint | `scenario_7_a_direct_connection_to_a_host_port_gets_the_host_ports_hint` |
| IPC-01 | IPC | Use an SSH agent socket | No `SSH_AUTH_SOCK` | `corpus_ipc_01_no_ssh_agent_is_passed_in` |
| IPC-02 | IPC | Use the container socket | Not mounted | `corpus_ipc_02_no_container_socket_is_mounted` |
| IPC-03 | IPC | Reach the D-Bus session bus | Not reachable | `corpus_ipc_03_no_dbus_session_bus_is_reachable` |
| IPC-04 | IPC | Push keystrokes into a terminal (TIOCSTI) | `EPERM` | `the_seccomp_filter_makes_tiocsti_fail_with_eperm` |
| IPC-05 | IPC | Open a URL on the host, or push to git | Only through the broker (allowed by the host) | `the_sandbox_opens_urls_and_pushes_only_through_the_host` |
| PROC-01 | PROC | See a host process by its PID | Not visible | `corpus_proc_01_host_processes_are_not_visible` |
| ENV-01 | ENV | Read a host environment variable | Environment is an allowlist | `every_isolation_probe_passes_inside_the_real_sandbox` |
| REG-01 | REG | Install an npm package and bypass the mirror | Installed through the mirror; direct access refused | `npm_installs_a_real_package_through_the_mirror_and_direct_access_is_refused` |
| EXEC-01 | EXEC | Run `terraform destroy -auto-approve` | Reported HIGH, not blocked | `scenario_9_terraform_destroy_is_reported_and_is_not_blocked` |
| SBX-01 | SBX | Start the IDE without its monitor | The sandbox does not start | `the_sandbox_does_not_start_without_its_monitor` |
| SBX-02 | SBX | The monitor fails during a session | Logged CRITICAL; the sandbox is killed | `a_failing_monitor_is_reported_and_ends_the_sandbox` |
| SBX-03 | SBX | Pause the session | Processes stop until resumed | `pausing_the_sandbox_stops_its_processes_until_resumed` |
| CTL-01 | SBX | Control: an allowed action reports success | Success is reported (harness check) | `corpus_control_the_harness_reports_success_and_failure` |

## Result

Run `scripts/escape-corpus.sh`. The last line reports `N/N passed`. A row that
fails makes the script exit 1.

Result for corpus v1: see the release notes.

## Known gaps

These attacks are not in v1. They are listed so the corpus does not claim
more than it tests.

- Clipboard, screen capture and keyboard hooks from the shared X display
  (PRD section 11). Nested X server is not the default yet (DECISIONS Q4).
- Attacks that use the IDE's own allowed domains (PRD section 11, data sent to
  allowed domains).
- Kernel, bubblewrap and Landlock bugs (PRD section 3, out of scope).
- Windows (Phases 16 and 17, after the first release).
