"""Separate bounded business/control and original-local lifecycle allocations."""
# SPDX-License-Identifier: Apache-2.0 OR MIT

# Existing schemas and raw journals keep their original aggregate ceiling.
MAX_STATE = 2 * 1024 * 1024
MAX_IDENTITY = 40 + 4 + 65536 + 2 + 8192
MAX_LOCAL_RECORD = 8 + 1 + 40 + 4 + 65536 + 1 + 152
MAX_LOCAL_METADATA = 2 * MAX_IDENTITY + MAX_LOCAL_RECORD + 1
# Version eight alone may add these authenticated records without consuming
# business capacity already committed under an older local session schema.
MAX_LOCAL_STATE = MAX_STATE + MAX_LOCAL_METADATA

# A common account has one roster/history plus one complete renewal transaction.
# Version nine keeps both outside the unchanged 2-MiB business/control budget.
MAX_ACCOUNT_RECORD = MAX_STATE
MAX_ACCOUNT_REQUEST = 32 * (65536 + 4) + 64
MAX_ACCOUNT_COORDINATION = MAX_ACCOUNT_REQUEST + 400
MAX_ACCOUNT_STATE = MAX_STATE + MAX_ACCOUNT_RECORD + MAX_ACCOUNT_COORDINATION + 20
# R's explicit scope and record discriminator sit outside the unchanged v9 budget.
MAX_ACCOUNT_ROSTER_COORDINATION = MAX_ACCOUNT_COORDINATION + 193
MAX_SHARED_STATE = MAX_ACCOUNT_STATE + 193

# P's bounded proof records have their own allocation; they never increase
# the business payload, existing G/R record limits or host directory quota.
MAX_POLICY_GRANT = 8 + 5 * 2 + 2 * (4 + 200 + 3373) + (4 + 2097 + 3373) + 8192 + 7618
MAX_POLICY_BASE_RECORD = 8 + 8 + 2 * (4 + MAX_POLICY_GRANT) + 1 + 152
# An older completed R retains one exact P proof after later policy adoption.
# While it is still the active P, the record uses a one-byte alias instead.
MAX_POLICY_RECORD = MAX_POLICY_BASE_RECORD + 13 + MAX_POLICY_GRANT
MAX_POLICY_STATE = MAX_SHARED_STATE + MAX_POLICY_RECORD + 48
