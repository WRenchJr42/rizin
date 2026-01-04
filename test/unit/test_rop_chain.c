// SPDX-FileCopyrightText: 2025 WRenchJr42 <yashas140304@gmail.com>
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

// Test 3: Compile chain.
bool test_rop_chain_compile(void) {
    RzCore *core = setup_test_core();
    
    RzRopChain *chain = rz_core_rop_chain_new(core, 0x7fffffffffff);
    rz_core_rop_chain_add_goal(chain, "rax", 0x3b);  // syscall num
   
    bool success = rz_core_rop_chain_compile(chain);
    mu_assert("Chain compilation should succeed", success);
    size_t chain_size;
    const ut8 *chain_bytes = rz_core_rop_chain_get_bytes(chain, &chain_size);
    mu_assert_notnull(chain_bytes, "Chain bytes should not be null");
    mu_assert("Chain should have 16 bytes", chain_size == 16);
    
    rz_core_rop_chain_free(chain);
    cleanup_test_core(core);
    mu_end;
}

// Test 4: Chain structure verification.
bool test_rop_chain_structure(void) {
    RzCore *core = setup_test_core();
    RzRopChain *chain = rz_core_rop_chain_new(core, 0x7fffffffffff);
    rz_core_rop_chain_add_goal(chain, "rax", 0x3b);  
    bool success = rz_core_rop_chain_compile(chain);
    mu_assert("Chain compilation should succeed", success);
    size_t chain_size;
    const ut8 *chain_bytes = rz_core_rop_chain_get_bytes(chain, &chain_size);
    mu_assert_notnull(chain_bytes, "Chain bytes should not be null");
    mu_assert("Chain should have 16 bytes", chain_size == 16);

    ut64 gadget_addr = 0;
    for (int i = 0; i < 8; i++) {
        gadget_addr |= ((ut64)chain_bytes[i]) << (i * 8);
    }

    // Extract value (next 8 bytes, little-endian)
    ut64 value = 0;
    for (int i = 0; i < 8; i++) {
        value |= ((ut64)chain_bytes[8 + i]) << (i * 8);
    }
    
    // Verify the value is what we set
    mu_assert_eq(value, 0x3b, "Value should be 0x3b");


    // Verify gadget address
    mu_assert("Gadget address should be non-zero", gadget_addr != 0);
    mu_assert("Gadget address should be < 0x100000000", gadget_addr < 0x100000000);
    
    // Log the gadget address and value
    printf("Found gadget at: 0x%016llx\n", (unsigned long long)gadget_addr);
    printf("With value: 0x%016llx\n", (unsigned long long)value);
    
    rz_core_rop_chain_free(chain);
    
    cleanup_test_core(core);
    mu_end;
}

// Test 5 : Multiple reggister goals.

bool test_rop_chain_multiple_goals(void) {
    RzCore *core = setup_test_core();
    RzRopChain *chain = rz_core_rop_chain_new(core, 0x7fffffffffff);
    rz_core_rop_chain_add_goal(chain, "rax", 0x3b);  
    rz_core_rop_chain_add_goal(chain, "rdi", 0x7fffffffe000);  
    bool success = rz_core_rop_chain_compile(chain);
    mu_assert("Chain compilation should succeed", success);
    size_t chain_size;
    const ut8 *chain_bytes = rz_core_rop_chain_get_bytes(chain, &chain_size);
    mu_assert_notnull(chain_bytes, "Chain bytes should not be null");
    mu_assert("Chain should have 32 bytes", chain_size == 32);

    // Extract first gadget address
    ut64 gadget1_addr = 0;
    for (int i = 0; i < 8; i++) {
        gadget1_addr |= ((ut64)chain_bytes[i]) << (i * 8);
    }
    // Extract first value
    ut64 value1 = 0;
    for (int i = 0; i < 8; i++) {
        value1 |= ((ut64)chain_bytes[8 + i]) << (i * 8);
    }
    // Extract second gadget address
    ut64 gadget2_addr = 0;
    for (int i = 0; i < 8; i++) {
        gadget2_addr |= ((ut64)chain_bytes[16 + i]) << (i * 8);
    }
    // Extract second value
    ut64 value2 = 0;
    for (int i = 0; i < 8; i++) {
        value2 |= ((ut64)chain_bytes[24 + i]) << (i * 8);
    }

    // Verify values
    mu_assert_eq(value1, 0x3b, "First value should be 0x3b");
    mu_assert_eq(value2, 0x7fffffffe000, "Second value should be 0x7fffffffe000");
    printf("Gadget 1 at: 0x%016llx with value: 0x%016llx\n", (unsigned long long)gadget1_addr, (unsigned long long)value1);
    printf("Gadget 2 at: 0x%016llx with value: 0x%016llx\n", (unsigned long long)gadget2_addr, (unsigned long long)value2);     

    rz_core_rop_chain_free(chain);
    
    cleanup_test_core(core);
    mu_end;
}

int all_tests(void) {
    mu_run_test(test_rop_chain_create);
    mu_run_test(test_rop_chain_goal);
    mu_run_test(test_rop_chain_compile);
    mu_run_test(test_rop_chain_structure);
    mu_run_test(test_rop_chain_multiple_goals);
    return tests_passed != tests_run;
}
mu_main(all_tests);

