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
MAX_SHARED_STATE = MAX_STATE + MAX_ACCOUNT_RECORD + MAX_ACCOUNT_COORDINATION + 20
