// SPDX-FileCopyrightText: 2025 Yashas <yashas140304@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_rop.h> 
#include <rz_core.h>
#include "minunit.h"
static RzCore *setup_test_core(void) {
    RzCore *core = rz_core_new();
    rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL);
    
    rz_core_file_open(core, "/bin/ls", RZ_PERM_R, 0);
    rz_core_bin_load(core, NULL, UT64_MAX);
    rz_core_analysis_all(core);
    
    return core;
}

static void cleanup_test_core(RzCore *core) {
    rz_core_free(core);
}

// Test 1: Create empty chain.
bool test_rop_chain_create(void) {
    RzCore *core = setup_test_core();

    RzRopChain *chain = rz_core_rop_chain_new(core,0x7fffffffffff);
    mu_assert_notnull(chain, "Failed to create ROP chain");
    rz_core_rop_chain_free(chain);
    
    cleanup_test_core(core);
    mu_end;
}

// Test 2: Add a simple goal.
bool test_rop_chain_goal(void) {
    RzCore *core = setup_test_core();

    // Goal: Set rax = 0x3b (syscall number for execve)
    RzRopChain *chain = rz_core_rop_chain_new(core,0x7fffffffffff);
    bool success = rz_core_rop_chain_add_goal(chain, "rax", 0x3b);
    mu_assert("Failed to add goal to ROP chain", success);

    //Verify 
    mu_assert_eq(rz_list_length(chain->goals), 1, "Goal count mismatch");
    RzRopGoal *goal = (RzRopGoal *)rz_list_get_n(chain->goals, 0);
    mu_assert_notnull(goal, "Goal is null");
    mu_assert_streq(goal->register_name, "rax", "Goal register mismatch");
    mu_assert_eq(goal->value, 0x3b, "Goal value mismatch");
    rz_core_rop_chain_free(chain);

    
    cleanup_test_core(core);
    mu_end;
}
/*
// Test 3: Can we compile a chain with multiple goals?
bool test_rop_chain_multi_goal(void) {
    RzCore *core = setup_test_core();
    
    // RzRopChain *chain = rz_core_rop_chain_new(core);
    // rz_core_rop_chain_add_goal(chain, "rax", 0x3b);  // syscall num
    // rz_core_rop_chain_add_goal(chain, "rdi", 0x1000); // arg1
    
    // bool success = rz_core_rop_chain_compile(chain);
    // mu_assert("Chain compilation failed", success);
    // mu_assert("Chain should have 4+ gadgets", chain->gadgets->length >= 4);
    
    cleanup_test_core(core);
    mu_end;
}

// Test 4: Does the chain have correct structure?
bool test_rop_chain_structure(void) {
    RzCore *core = setup_test_core();
    
    // RzRopChain *chain = rz_core_rop_chain_new(core);
    // rz_core_rop_chain_add_goal(chain, "rax", 0x5);
    // rz_core_rop_chain_compile(chain);
    
    // Expected structure:
    // [gadget_addr, 0x5]  // pop rax; ret + value
    
    // ut8 *bytes = rz_core_rop_chain_get_bytes(chain);
    // mu_assert_notnull(bytes, "No chain bytes generated");
    
    cleanup_test_core(core);
    mu_end;
}*/

int all_tests(void) {
    mu_run_test(test_rop_chain_create);
    mu_run_test(test_rop_chain_goal);
    //mu_run_test(test_rop_chain_multi_goal);
    //mu_run_test(test_rop_chain_structure);
    return tests_passed != tests_run;
}
mu_main(all_tests);


/*bool test_placeholder(void) {
    mu_assert("placeholder", 1 == 1);
    mu_end;
}

bool all_tests(void) {
    mu_run_test(test_placeholder);
    return tests_passed != tests_run;
}

mu_main(all_tests)*/