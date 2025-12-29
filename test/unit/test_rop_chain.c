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

// Test 1: Can we create an empty chain?
bool test_rop_chain_create(void) {
    RzCore *core = setup_test_core();

    RzRopChain *chain = rz_core_rop_chain_new(core,0x7fffffffffff);
    mu_assert_notnull(chain, "Failed to create ROP chain");
    rz_core_rop_chain_free(chain);
    
    cleanup_test_core(core);
    mu_end;
}
/*
// Test 2: Can we add a simple goal (set rax=0x3b)?
bool test_rop_chain_simple_goal(void) {
    RzCore *core = setup_test_core();

    // RzRopChain *chain = rz_core_rop_chain_new(core);
    // rz_core_rop_chain_add_goal(chain, "rax", 0x3b);
    
    // Should find "pop rax; ret" gadget automatically
    // mu_assert("Should have found pop rax gadget", chain->gadgets->length > 0);
    
    cleanup_test_core(core);
    mu_end;
}

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
    //mu_run_test(test_rop_chain_simple_goal);
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