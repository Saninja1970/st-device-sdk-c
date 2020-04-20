/* ***************************************************************************
 *
 * Copyright (c) 2020 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <iot_error.h>
#include <iot_internal.h>
#include <iot_os_util.h>
#include <iot_easysetup.h>
#include <string.h>
#include "TC_MOCK_functions.h"

#define UNUSED(x) (void**)(x)

static char device_info_sample[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \"MyTestingFirmwareVersion\",\n"
        "\t\t\"privateKey\": \"privateKey_here\",\n"
        "\t\t\"publicKey\": \"publicKey_here\",\n"
        "\t\t\"serialNumber\": \"serialNumber_here\"\n"
        "\t}\n"
        "}"
};

int TC_iot_api_memleak_detect_setup(void **state)
{
    UNUSED(state);
    set_mock_detect_memory_leak(true);
    return 0;
}

int TC_iot_api_memleak_detect_teardown(void **state)
{
    UNUSED(state);
    set_mock_detect_memory_leak(false);
    return 0;
}

void TC_iot_api_device_info_load_null_parameters(void **state)
{
    iot_error_t err;
    struct iot_device_info info;
    UNUSED(state);

    // When: All parameters null
    err = iot_api_device_info_load(NULL, 10, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: device_info is null
    err = iot_api_device_info_load(NULL, 10, &info);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: info is null
    err = iot_api_device_info_load(device_info_sample, sizeof(device_info_sample), NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_api_device_info_load_success(void **state)
{
    iot_error_t err;
    struct iot_device_info info;
    UNUSED(state);

    // When: valid input
    err = iot_api_device_info_load(device_info_sample, sizeof(device_info_sample), &info);
    // Then: success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal("MyTestingFirmwareVersion", info.firmware_version);

    // local teardown
    iot_api_device_info_mem_free(&info);
}

void TC_iot_api_device_info_load_internal_failure(void **state)
{
    iot_error_t err;
    struct iot_device_info info;
    UNUSED(state);

    for (unsigned int i = 0; i < 2; i++) {
        // Given: i-th malloc failure
        memset(&info, '\0', sizeof(struct iot_device_info));
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // When: valid input
        err = iot_api_device_info_load(device_info_sample, sizeof(device_info_sample), &info);
        // Then: success
        assert_int_not_equal(err, IOT_ERROR_NONE);
        // local teardown
        iot_api_device_info_mem_free(&info);
    }

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

static char device_info_sample_without_firmware_version[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"privateKey\": \"privateKey_here\",\n"
        "\t\t\"publicKey\": \"publicKey_here\",\n"
        "\t\t\"serialNumber\": \"serialNumber_here\"\n"
        "\t}\n"
        "}"
};

void TC_iot_api_device_info_load_without_firmware_version(void **state)
{
    iot_error_t err;
    struct iot_device_info info;
    UNUSED(state);

    // Given
    memset(&info, '\0', sizeof(struct iot_device_info));
    // When: malformed json
    err = iot_api_device_info_load(device_info_sample_without_firmware_version, sizeof(device_info_sample_without_firmware_version), &info);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // local teardown
    iot_api_device_info_mem_free(&info);
}

static char onboarding_profile_template[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"NAME\",\n"
        "    \"mnId\": \"MNID\",\n"
        "    \"setupId\": \"999\",\n"
        "    \"vid\": \"VID\",\n"
        "    \"deviceTypeId\": \"TYPE\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\",\n"
        "      \"BUTTON\",\n"
        "      \"PIN\",\n"
        "      \"QR\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519_or_CERTIFICATE\",\n"
        "    \"deviceIntegrationProfileKey\": {\n"
        "      \"id\": \"DIP_ID\",\n"
        "      \"majorVersion\": 9999,\n"
        "      \"minorVersion\": 9999\n"
        "    }\n"
        "  }\n"
        "}"
};

void TC_iot_api_onboarding_config_load_null_parameters(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // When: All parameters null
    err = iot_api_onboarding_config_load(NULL, 0, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: NULL pointer at output parameter
    err = iot_api_onboarding_config_load(onboarding_profile_template, sizeof(onboarding_profile_template), NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: NULL pointer at output parameter
    err = iot_api_onboarding_config_load(NULL, 0, &devconf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_api_onboarding_config_load_template_parameters(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // Given
    memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
    // When: template is used as parameter
    err = iot_api_onboarding_config_load(onboarding_profile_template, sizeof(onboarding_profile_template), &devconf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // local teardown
    iot_api_onboarding_config_mem_free(&devconf);
}

static char onboarding_profile_example[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"mnId\": \"fTST\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\",\n"
        "      \"BUTTON\",\n"
        "      \"PIN\",\n"
        "      \"QR\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\",\n"
        "    \"deviceIntegrationProfileKey\": {\n"
        "      \"id\": \"bb000ddd-92a0-42a3-86f0-b531f278af06\",\n"
        "      \"majorVersion\": 0,\n"
        "      \"minorVersion\": 1\n"
        "    }\n"
        "  }\n"
        "}"
};

void TC_iot_api_onboarding_config_load_success(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    struct iot_uuid target_id = {
			.id = {0xbb, 0x00, 0x0d, 0xdd, 0x92, 0xa0, 0x42, 0xa3,
				0x86, 0xf0, 0xb5, 0x31, 0xf2, 0x78, 0xaf, 0x06}
    };
    UNUSED(state);

    // When: valid parameters
    err = iot_api_onboarding_config_load(onboarding_profile_example, sizeof(onboarding_profile_example), &devconf);
    // Then: success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal("STDK", devconf.device_onboarding_id);
    assert_string_equal("fTST", devconf.mnid);
    assert_string_equal("001", devconf.setupid);
    assert_string_equal("STDK_BULB_0001", devconf.vid);
    assert_string_equal("Switch", devconf.device_type);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_BUTTON);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_JUSTWORKS);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_PIN);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_QR);
    assert_memory_equal(&target_id, &devconf.dip->dip_id, sizeof(struct iot_uuid));

    // Local teardown
    iot_api_onboarding_config_mem_free(&devconf);
}

void TC_iot_api_onboarding_config_load_internal_failure(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    for (unsigned int i = 0; i < 7; i++) {
        // Given: i-th malloc failure
        memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // When: valid parameters
        err = iot_api_onboarding_config_load(onboarding_profile_example, sizeof(onboarding_profile_example), &devconf);
        // Then: failure
        assert_int_not_equal(err, IOT_ERROR_NONE);
        // Local teardown
        iot_api_onboarding_config_mem_free(&devconf);
    }

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

static char onboarding_profile_without_mnid[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\",\n"
        "      \"BUTTON\",\n"
        "      \"PIN\",\n"
        "      \"QR\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\",\n"
        "    \"deviceIntegrationProfileKey\": {\n"
        "      \"id\": \"bb000ddd-92a0-a2a3-46f0-b531f278af06\",\n"
        "      \"majorVersion\": 0,\n"
        "      \"minorVersion\": 1\n"
        "    }\n"
        "  }\n"
        "}"
};

void TC_iot_api_onboarding_config_without_mnid(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // Given
    memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
    // When: malformed parameters
    err = iot_api_onboarding_config_load(onboarding_profile_without_mnid, sizeof(onboarding_profile_without_mnid), &devconf);
    // Then: returns fail
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    iot_api_onboarding_config_mem_free(&devconf);
}

static char onboarding_profile_without_dip_id[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"mnId\": \"fTST\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\",\n"
        "      \"BUTTON\",\n"
        "      \"PIN\",\n"
        "      \"QR\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\",\n"
        "    \"deviceIntegrationProfileKey\": {\n"
        "      \"majorVersion\": 0,\n"
        "      \"minorVersion\": 1\n"
        "    }\n"
        "  }\n"
        "}"
};

void TC_iot_api_onboarding_config_without_dip_id(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // Given
    memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
    // When: malformed parameters
    err = iot_api_onboarding_config_load(onboarding_profile_without_dip_id, sizeof(onboarding_profile_without_dip_id), &devconf);
    // Then: returns fail
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    iot_api_onboarding_config_mem_free(&devconf);
}

void TC_iot_get_time_in_sec_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: null parameters
    err = iot_get_time_in_sec(NULL, 0);
    // Then: return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_time_in_sec_success(void **state)
{
    iot_error_t err;
    char time_buffer[32];
    UNUSED(state);

    // Given
    memset(time_buffer, '\0', sizeof(time_buffer));
    // When: valid parameters
    err = iot_get_time_in_sec(time_buffer, sizeof(time_buffer));
    // Then: return success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(strlen(time_buffer) > 0);
    assert_int_not_equal(atol(time_buffer), 0);
}

void TC_iot_get_time_in_ms_null_parmaeters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: null parameters
    err = iot_get_time_in_ms(NULL, 0);
    // Then: return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_time_in_ms_success(void **state)
{
    iot_error_t err;
    char time_buffer[32];
    UNUSED(state);

    // Given
    memset(time_buffer, '\0', sizeof(time_buffer));
    // When: valid parameters
    err = iot_get_time_in_ms(time_buffer, sizeof(time_buffer));
    // Then: return success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(strlen(time_buffer) > 0);
    assert_int_not_equal(atol(time_buffer), 0);
}

void TC_iot_get_time_in_sec_by_long_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: null parameter
    err = iot_get_time_in_sec_by_long(NULL);
    // Then: return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_time_in_sec_by_long_success(void **state)
{
    iot_error_t err;
    long seconds = 0;
    UNUSED(state);

    // When: valid parameter
    err = iot_get_time_in_sec_by_long(&seconds);
    // Then: return success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(seconds > 0);
}

void TC_iot_easysetup_request_success(void **state)
{
    iot_error_t err;
    int os_ret;
    struct iot_context *context;
    const char *test_payload = "{ message: \"\" }";
    struct iot_easysetup_payload received_payload;
    unsigned int easysetup_event = 0;
    UNUSED(state);

    // Given
    context = (struct iot_context*) calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->easysetup_req_queue = iot_os_queue_create(1, sizeof(struct iot_easysetup_payload));
    assert_non_null(context->easysetup_req_queue);
    context->iot_events = iot_os_eventgroup_create();
    assert_non_null(context->iot_events);

    // When
    err = iot_easysetup_request(context, IOT_EASYSETUP_STEP_DEVICEINFO, test_payload);

    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    easysetup_event = iot_os_eventgroup_wait_bits(context->iot_events,
            IOT_EVENT_BIT_EASYSETUP_REQ, true, false, IOT_MAIN_TASK_CYCLE);
    assert_int_not_equal(easysetup_event, 0);
    os_ret = iot_os_queue_receive(context->easysetup_req_queue, &received_payload, 0);
    assert_int_equal(os_ret, IOT_OS_TRUE);
    assert_string_equal(received_payload.payload, test_payload);

    // Teardown
    iot_os_queue_delete(context->easysetup_req_queue);
    iot_os_eventgroup_delete(context->iot_events);
    free(context);
}
