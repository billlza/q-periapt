# Maintenance preparation fixture boundary

The complete hosted artifact suite for PR revision `42c357ae` checked out
GitHub's actual merge commit `008d323106284de5775213d5ee4a809288ed1f36` and ran
4,013 tests with one error and three existing platform skips. The only error was
`test_offline_prepare_stages_only_seven_platform_assets_and_two_requests`.
The original [CI job](https://github.com/billlza/q-periapt/actions/runs/44021520630/job/133831994332),
uploaded artifact, exact source pin and local reproduction are retained here.

Factoring the common preparation engine added a committed-admission recheck
before staging. This offline unit fixture already substituted the pending-plan
builder, release assets, account directories and final verifier, but had not
modeled the new recheck. Its synthetic P2 digest therefore reached the real
`artifact/results.json` reader, which correctly refused it. The same single
test failed locally before the fixture correction.

The corrected fixture supplies its explicit synthetic admission at that
boundary. It first makes the admission fail and asserts that no asset is
staged and no preparation intent or plan exists. It then admits the fixture
and retains the original exact seven-platform-asset, two-request, account-lock,
credential-free and network-free assertions. It also asserts both exact
admission calls and the single permitted staging call. Production validation,
source selection, journal behavior and all failure checks remain unchanged.

This correction is a test-integration change. The original failed cohort and
its source-specific packages remain original evidence; the final release uses
the subsequently qualified source and its explicitly selected artifacts.

The expanded local publication and maintenance regression runs 256 tests with
zero failures, errors or skips and warnings treated as errors. The retained
red and green logs distinguish the actual failure from the repaired fixture.
The CI merge commit remains distinct from the PR head and from any later main
merge commit; final producer and qualification records must retain their actual
checked-out source identities.
