// SPDX-FileCopyrightText: 2025 WRenchJr42 <yashas140304@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_rop.h>

/**
* \brief Free a ROP goal
*/

static void rop_goal_free(void *data) {
    RzRopGoal *goal = (RzRopGoal *)data;
    if (!goal) {
        return;
    }
    free(goal->register_name);
    free(goal);
}
/**
 * \brief Create a new ROP chain
 */
RZ_OWN RzRopChain *rz_core_rop_chain_new(RZ_NONNULL RzCore *core, ut64 stack_addr) {
    rz_return_val_if_fail(core, NULL);

    RzRopChain *chain = RZ_NEW0(RzRopChain);
    if (!chain) {
        return NULL;
    }
    chain->core = core;
    chain->stack_addr = stack_addr;
    chain->goals = rz_list_newf(rop_goal_free);
    chain->gadgets = rz_list_new();
    chain->buffer = rz_buf_new_with_bytes(NULL,0);
    chain->compiled = false;

    if (!chain->goals || !chain->gadgets || !chain->buffer) {
        rz_core_rop_chain_free(chain);
        return NULL;
    }
    return chain;
}

/**
 * \brief Free a ROP chain
 */
void rz_core_rop_chain_free(RZ_NULLABLE RzRopChain *chain) {
    if (!chain) {
        return;
    }
    rz_list_free(chain->goals);
    rz_list_free(chain->gadgets);
    rz_buf_free(chain->buffer);
    free(chain);
}   

/**
 * \brief Add a goal to the ROP chain
 */
 RZ_API bool rz_core_rop_chain_add_goal(RZ_NONNULL RzRopChain *chain, RZ_NONNULL const char *reg, ut64 value) {
    rz_return_val_if_fail(chain, false);
    rz_return_val_if_fail(reg, false);

    RzRopGoal *goal = RZ_NEW0(RzRopGoal);
    if (!goal) {
        return false;
    }
    goal->register_name = strdup(reg);
    goal->value = value;
    if (!goal->register_name) {
        free(goal);
        return false;
    }

    rz_list_append(chain->goals, goal);
    return true;

}

/**
* \brief Find a gadget that meets the specified goal
* \return Address of gadget, 0 if not found
*/
static ut64 find_gadget(RZ_NONNULL RzCore *core,RZ_NONNULL  const char *register_name)
{
    rz_return_val_if_fail(core && register_name, 0);

    char *cmd = rz_str_newf("/R pop %s", register_name);
    if (!cmd) {
        return 0;
    }
    RZ_LOG_INFO("Searching for gadget with command: %s\n", cmd);
    
    // Execute ROP search command
    char *result = rz_core_cmd_str(core, cmd);
    free(cmd);
    if (!result || strlen(result) == 0) {
        RZ_LOG_WARN("No gadget found for register: %s\n", register_name);
        free(result);
        return 0;
    }
    // Parse address from result
    ut64 gadget_addr = 0;
    const char *line = result;
    if (sscanf(line, " 0x%" PFMT64x, &gadget_addr) == 1) {
        RZ_LOG_INFO("Found gadget at address: 0x%" PFMT64x "\n", gadget_addr);
    } else {
        RZ_LOG_ERROR("Failed to parse gadget address from: %s\n", line);
    }
    free(result);
    return gadget_addr; 
}

/**
 * \brief Get the compiled ROP chain bytes
 */
 RZ_API RZ_BORROW const ut8 *rz_core_rop_chain_get_bytes(RZ_NONNULL RzRopChain *chain, RZ_NONNULL RZ_OUT size_t *size) {
    rz_return_val_if_fail(chain, NULL);
    rz_return_val_if_fail(size, NULL);

    if (!chain->compiled) {
        RZ_LOG_ERROR("ROP chain not compiled yet.\n");
        return NULL;
    }
    ut64 size64 = 0;
    const ut8 *data = rz_buf_data(chain->buffer, &size64);  
    *size = (size_t)size64;
    return data;
}

RZ_API bool rz_core_rop_chain_compile(RZ_NONNULL RzRopChain *chain) {
    rz_return_val_if_fail(chain, false);    
    RzListIter *iter;
    RzRopGoal *goal;
    rz_list_foreach (chain->goals, iter, goal) {
        ut64 gadget_addr = find_gadget(chain->core, goal->register_name);
        if (gadget_addr == 0) {
            RZ_LOG_ERROR("Failed to find gadget for goal: %s = 0x%" PFMT64x "\n", goal->register_name, goal->value);
            return false;
        }
        RZ_LOG_INFO("Found gadget 0x%" PFMT64x " for goal: %s = 0x%" PFMT64x "\n", gadget_addr, goal->register_name, goal->value);  

        ut8 addr_bytes[8];
        rz_write_le64(addr_bytes, gadget_addr);
        rz_buf_append_bytes(chain->buffer, addr_bytes, 8);

        ut8 val_bytes[8];
        rz_write_le64(val_bytes, goal->value);
        rz_buf_append_bytes(chain->buffer, val_bytes, 8);


    }
    chain->compiled = true;
    return true;
}