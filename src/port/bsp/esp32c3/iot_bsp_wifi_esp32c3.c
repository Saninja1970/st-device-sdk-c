/* ***************************************************************************
 *
 * Copyright (c) 2019-2022 Samsung Electronics All Rights Reserved.
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

#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#include "esp_idf_version.h"
#if (ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(4,0,0))
#include "esp32/rom/ets_sys.h"
#else
#include "rom/ets_sys.h"
#endif
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"

#include "iot_debug.h"
#include "iot_bsp_wifi.h"
#include "iot_os_util.h"
#include "iot_util.h"

#include "lwip/apps/sntp.h"

#define EXAMPLE_ESP_WIFI_SSID      "Wokwi-GUEST"
#define EXAMPLE_ESP_WIFI_PASS      ""
#define EXAMPLE_ESP_MAXIMUM_RETRY  10

#define DUMMY_TARGET_WIFI_SSID    "AnnapornaSF"

//uint8_t DUMMY_TARGET_WIFI_BSSID[] = {0X4A , 0X1E , 0XBB , 0XEC , 0XA8 , 0XC7 };

uint8_t DUMMY_TARGET_WIFI_BSSID[] = {0XE8 , 0X48 , 0XB8 , 0XE0 , 0X8D , 0X90 };

const int WIFI_STA_START_BIT 		= BIT0;
const int WIFI_STA_CONNECT_BIT		= BIT1;
const int WIFI_STA_DISCONNECT_BIT	= BIT2;
const int WIFI_AP_START_BIT 			= BIT3;
const int WIFI_AP_STOP_BIT 			= BIT4;

const int WIFI_EVENT_BIT_ALL = BIT0|BIT1|BIT2|BIT3|BIT4;

static int WIFI_INITIALIZED = false;
static EventGroupHandle_t wifi_event_group;
static iot_bsp_wifi_event_cb_t wifi_event_cb;

static system_event_cb_t s_event_handler_cb = NULL;
static void *s_event_ctx = NULL;
static bool s_initialized = false;
static iot_error_t s_latest_disconnect_reason;

ESP_EVENT_DEFINE_BASE(SYSTEM_EVENT);

static void _initialize_sntp(void)
{
	IOT_INFO("Initializing SNTP");
	if (sntp_enabled()) {
		IOT_INFO("SNTP is already working, STOP it first");
		sntp_stop();
	}

	sntp_setoperatingmode(SNTP_OPMODE_POLL);
	sntp_setservername(0, "pool.ntp.org");
	sntp_setservername(1, "1.kr.pool.ntp.org");
	sntp_setservername(2, "1.asia.pool.ntp.org");
	sntp_setservername(3, "us.pool.ntp.org");
	sntp_setservername(4, "1.cn.pool.ntp.org");
	sntp_setservername(5, "1.hk.pool.ntp.org");
	sntp_setservername(6, "europe.pool.ntp.org");
	sntp_setservername(7, "time1.google.com");

	sntp_init();
}

static void _obtain_time(void)
{
	time_t now = 0;
	struct tm timeinfo = { 0 };
	int retry = 0;
	const int retry_count = 10;

	_initialize_sntp();

	while (timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count) {
		IOT_INFO("Waiting for system time to be set... (%d/%d)", retry, retry_count);
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_BSP_WIFI_SNTP_FAIL, retry, retry_count);
		IOT_DELAY(2000);
		time(&now);
		localtime_r(&now, &timeinfo);
	}

	sntp_stop();

	if (retry < 10) {
		IOT_INFO("[WIFI] system time updated by %ld", now);
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_BSP_WIFI_SNTP_SUCCESS, now, retry);
	}
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
	wifi_ap_record_t ap_info;
	memset(&ap_info, 0x0, sizeof(wifi_ap_record_t));

	switch(event->event_id) {
	case SYSTEM_EVENT_STA_START:
		xEventGroupSetBits(wifi_event_group, WIFI_STA_START_BIT);
		esp_wifi_connect();
		break;

	case SYSTEM_EVENT_STA_STOP:
		IOT_INFO("SYSTEM_EVENT_STA_STOP");
		xEventGroupClearBits(wifi_event_group, WIFI_EVENT_BIT_ALL);
		break;

	case SYSTEM_EVENT_STA_DISCONNECTED:
		IOT_INFO("Disconnect reason : %d", event->event_info.disconnected.reason);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_EVENT_DEAUTH, event->event_info.disconnected.reason, 0);
		xEventGroupSetBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT);
		switch (event->event_info.disconnected.reason)
		{
			case WIFI_REASON_NO_AP_FOUND:
				s_latest_disconnect_reason = IOT_ERROR_CONN_STA_AP_NOT_FOUND;
				break;
			case WIFI_REASON_AUTH_FAIL:
				s_latest_disconnect_reason = IOT_ERROR_CONN_STA_AUTH_FAIL;
				break;
			case WIFI_REASON_ASSOC_FAIL:
				s_latest_disconnect_reason = IOT_ERROR_CONN_STA_ASSOC_FAIL;
				break;
		}
		esp_wifi_connect();
		xEventGroupClearBits(wifi_event_group, WIFI_STA_CONNECT_BIT);
		break;

	case SYSTEM_EVENT_STA_GOT_IP:
		esp_wifi_sta_get_ap_info(&ap_info);
		IOT_INFO("got ip:%s rssi:%ddBm",
			ip4addr_ntoa((ip4_addr_t *)&event->event_info.got_ip.ip_info.ip), ap_info.rssi);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_EVENT_AUTH, ap_info.rssi, 0);
		xEventGroupSetBits(wifi_event_group, WIFI_STA_CONNECT_BIT);
		xEventGroupClearBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT);
		break;

	case SYSTEM_EVENT_AP_START:
		xEventGroupClearBits(wifi_event_group, WIFI_EVENT_BIT_ALL);
		IOT_INFO("SYSTEM_EVENT_AP_START");
		xEventGroupSetBits(wifi_event_group, WIFI_AP_START_BIT);
		break;

	case SYSTEM_EVENT_AP_STOP:
		IOT_INFO("SYSTEM_EVENT_AP_STOP");
		xEventGroupSetBits(wifi_event_group, WIFI_AP_STOP_BIT);
		break;

	case SYSTEM_EVENT_AP_STACONNECTED:
		IOT_INFO("station:"MACSTR" join, AID=%d",
				MAC2STR(event->event_info.sta_connected.mac),
				event->event_info.sta_connected.aid);
		if (wifi_event_cb) {
			IOT_DEBUG("0x%p called", wifi_event_cb);
			(*wifi_event_cb)(IOT_WIFI_EVENT_SOFTAP_STA_JOIN, IOT_ERROR_NONE);
		}
		break;

	case SYSTEM_EVENT_AP_STADISCONNECTED:
		IOT_INFO("station:"MACSTR" leave, AID=%d",
				MAC2STR(event->event_info.sta_disconnected.mac),
				event->event_info.sta_disconnected.aid);

		xEventGroupSetBits(wifi_event_group, WIFI_AP_STOP_BIT);
		if (wifi_event_cb) {
			IOT_DEBUG("0x%p called", wifi_event_cb);
			(*wifi_event_cb)(IOT_WIFI_EVENT_SOFTAP_STA_LEAVE, IOT_ERROR_NONE);
		}
		break;

	default:
		IOT_INFO("event_handler = %d", event->event_id);
		break;
	}

	return ESP_OK;
}

static void esp_event_post_to_user(void* arg, esp_event_base_t base, int32_t id, void* data)
{
	if (s_event_handler_cb) {
		system_event_t* event = (system_event_t*) data;
		(*s_event_handler_cb)(s_event_ctx, event);
	}
}

esp_err_t esp_event_send_legacy(system_event_t *event)
{
	if (!s_initialized) {
		IOT_ERROR("system event loop not initialized via esp_event_loop_init");
		return ESP_ERR_INVALID_STATE;
	}

	return esp_event_post(SYSTEM_EVENT, event->event_id, event, sizeof(*event), portMAX_DELAY);
}

static esp_err_t esp_event_loop_init_wrap(system_event_cb_t cb, void *ctx)
{
	if (s_initialized) {
		IOT_ERROR("system event loop already initialized");
		return ESP_ERR_INVALID_STATE;
	}

	esp_err_t err = esp_event_loop_create_default();
	if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
		IOT_ERROR("esp_event_loop_create_default is failed");
		return err;
	}

	err = esp_event_handler_register(SYSTEM_EVENT, ESP_EVENT_ANY_ID, esp_event_post_to_user, NULL);
	if (err != ESP_OK) {
		IOT_ERROR("esp_event_handler_register is failed");
		esp_event_loop_delete_default();
		return err;
	}

	s_initialized = true;
	s_event_handler_cb = cb;
	s_event_ctx = ctx;
	return ESP_OK;
}

iot_error_t iot_bsp_wifi_init()
{
	esp_err_t esp_ret;

	IOT_INFO("[esp32c3] iot_bsp_wifi_init");

	if(WIFI_INITIALIZED)
		return IOT_ERROR_NONE;

	wifi_event_group = xEventGroupCreate();

	esp_netif_init();
	esp_ret = esp_event_loop_init_wrap(event_handler, NULL);
	if(esp_ret != ESP_OK) {
		IOT_ERROR("esp_event_loop_init_wrap failed err=[%d]", esp_ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_INIT_FAIL, esp_ret, __LINE__);
		return IOT_ERROR_INIT_FAIL;
	}

	esp_netif_create_default_wifi_sta();
	esp_netif_create_default_wifi_ap();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	esp_ret = esp_wifi_init(&cfg);
	if(esp_ret != ESP_OK) {
		IOT_ERROR("esp_wifi_init failed err=[%d]", esp_ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_INIT_FAIL, esp_ret, __LINE__);
		return IOT_ERROR_INIT_FAIL;
	}

	esp_ret = esp_wifi_set_storage(WIFI_STORAGE_RAM);
	if(esp_ret != ESP_OK) {
		IOT_ERROR("esp_wifi_set_storage failed err=[%d]", esp_ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_INIT_FAIL, esp_ret, __LINE__);
		return IOT_ERROR_INIT_FAIL;
	}

	esp_ret = esp_wifi_set_mode(WIFI_MODE_NULL);
	if(esp_ret != ESP_OK) {
		IOT_ERROR("esp_wifi_set_mode failed err=[%d]", esp_ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_INIT_FAIL, esp_ret, __LINE__);
		return IOT_ERROR_INIT_FAIL;
	}

	WIFI_INITIALIZED = true;
	IOT_INFO("[esp32c3] iot_bsp_wifi_init done");
	IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_BSP_WIFI_INIT_SUCCESS, 0, 0);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_wifi_set_mode(iot_wifi_conf *conf)
{
	int str_len = 0;
	wifi_config_t wifi_config;
	time_t now;
	struct tm timeinfo;
	wifi_mode_t mode = WIFI_MODE_NULL;
	EventBits_t uxBits = 0;
	esp_err_t esp_ret;

	memset(&wifi_config, 0x0, sizeof(wifi_config_t));

	IOT_INFO("iot_bsp_wifi_set_mode = %d", conf->mode);
	IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_BSP_WIFI_SETMODE, conf->mode, 0);

	switch(conf->mode) {
	case IOT_WIFI_MODE_OFF:

		esp_ret = esp_wifi_set_mode(WIFI_MODE_NULL);
		if(esp_ret != ESP_OK) {
			IOT_ERROR("esp_wifi_set_mode failed err=[%d]", esp_ret);
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_SETMODE_FAIL, conf->mode, esp_ret);
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}
		break;

	case IOT_WIFI_MODE_SCAN:
		esp_ret = esp_wifi_get_mode(&mode);
		if(esp_ret != ESP_OK) {
			IOT_ERROR("esp_wifi_get_mode failed err=[%d]", esp_ret);
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_SETMODE_FAIL, conf->mode, esp_ret);
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}

		if(mode == WIFI_MODE_NULL) {
			ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
			ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
			ESP_ERROR_CHECK(esp_wifi_start());

			uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_STA_START_BIT,
			true, false, IOT_WIFI_CMD_TIMEOUT);

			if(uxBits & WIFI_STA_START_BIT) {
				IOT_INFO("WiFi Station Started");
			}
			else {
				IOT_ERROR("WIFI_STA_START_BIT event timeout");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
		}
		break;

	case IOT_WIFI_MODE_STATION:
/*esp_ret = esp_wifi_get_mode(&mode);
		if(esp_ret != ESP_OK) {
			IOT_ERROR("esp_wifi_get_mode failed err=[%d]", esp_ret);
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_SETMODE_FAIL, conf->mode, esp_ret);
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}

		//AP connection is not allowed in WIFI_MODE_APSTA and WIFI_MODE_AP
		if(mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) {
			IOT_INFO("[esp32s2] current mode=%d need to call esp_wifi_stop", mode);
			ESP_ERROR_CHECK(esp_wifi_stop());

			uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_AP_STOP_BIT,
					true, false, IOT_WIFI_CMD_TIMEOUT);

			if(uxBits & WIFI_AP_STOP_BIT) {
				IOT_INFO("AP Mode stopped");
				IOT_DELAY(500);
			}
			else {
				IOT_ERROR("WIFI_AP_STOP_BIT event Timeout");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
		}

		str_len = strlen(conf->ssid);
		if(str_len) {
			memcpy(wifi_config.sta.ssid, conf->ssid, (str_len > IOT_WIFI_MAX_SSID_LEN) ? IOT_WIFI_MAX_SSID_LEN : str_len);
		}

		str_len = strlen(conf->pass);
		if(str_len) {
			memcpy(wifi_config.sta.password, conf->pass, (str_len > IOT_WIFI_MAX_PASS_LEN) ? IOT_WIFI_MAX_PASS_LEN : str_len);
		}

		str_len = strlen((char *)conf->bssid);
		if(str_len) {
			memcpy(wifi_config.sta.bssid, conf->bssid, IOT_WIFI_MAX_BSSID_LEN);
			wifi_config.sta.bssid_set = true;

			IOT_DEBUG("target mac=%2X:%2X:%2X:%2X:%2X:%2X",
					wifi_config.sta.bssid[0], wifi_config.sta.bssid[1], wifi_config.sta.bssid[2],
					wifi_config.sta.bssid[3], wifi_config.sta.bssid[4], wifi_config.sta.bssid[5]);
		}

		if (conf->authmode == IOT_WIFI_AUTH_WPA3_PERSONAL) {
			wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA3_PSK;
			// set PMF (Protected Management Frames) optional mode for better compatibility
			wifi_config.sta.pmf_cfg.capable = true;
			wifi_config.sta.pmf_cfg.required = false;
		}
		s_latest_disconnect_reason = IOT_ERROR_CONN_CONNECT_FAIL;

		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
		ESP_ERROR_CHECK(esp_wifi_start());

		IOT_INFO("connect to ap SSID:%s", wifi_config.sta.ssid);

		uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_STA_CONNECT_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT);
		if((uxBits & WIFI_STA_CONNECT_BIT)) {
			IOT_INFO("AP Connected");
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_CONNECT_SUCCESS, 0, 0);
		}
		else {
			iot_error_t err = IOT_ERROR_CONN_CONNECT_FAIL;
			if (s_latest_disconnect_reason != IOT_ERROR_CONN_CONNECT_FAIL) {
				err = s_latest_disconnect_reason;
			}

			IOT_ERROR("WIFI_STA_CONNECT_BIT event Timeout %d", err);
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_CONNECT_FAIL, IOT_WIFI_CMD_TIMEOUT, err);
			return err;
		}

		time(&now);
		localtime_r(&now, &timeinfo);

		if (timeinfo.tm_year < (2016 - 1900)) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_obtain_time();
		}*/


		break;

	case IOT_WIFI_MODE_SOFTAP:

		esp_ret = esp_wifi_get_mode(&mode);
		if(esp_ret != ESP_OK) {
			IOT_ERROR("esp_wifi_get_mode failed err=[%d]", esp_ret);
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_SETMODE_FAIL, conf->mode, esp_ret);
			return IOT_ERROR_CONN_OPERATE_FAIL;
		}

		/*AP connection is not allowed in WIFI_MODE_APSTA and WIFI_MODE_AP*/
		if(mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA ) {
			IOT_INFO("[esp32c3] current mode=%d need to call esp_wifi_stop", mode);
			ESP_ERROR_CHECK(esp_wifi_stop());

			uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_AP_STOP_BIT,
					true, false, IOT_WIFI_CMD_TIMEOUT);

			if(uxBits & WIFI_AP_STOP_BIT) {
				IOT_INFO("AP Mode stopped");
				IOT_DELAY(500);
			}
			else {
				IOT_ERROR("WIFI_AP_STOP_BIT event Timeout");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}
		}

		if(mode == WIFI_MODE_STA ) {
			IOT_INFO("[esp32s2] current mode=%d need to call esp_wifi_stop", mode);
			ESP_ERROR_CHECK(esp_wifi_stop());

			/*uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_STA_DISCONNECT_BIT,true, false, IOT_WIFI_CMD_TIMEOUT);

			if(uxBits & WIFI_STA_DISCONNECT_BIT) {
				IOT_INFO("STA Mode stopped");
				IOT_DELAY(500);
			}
			else {
				IOT_ERROR("WIFI_STA_DISCONNECT_BIT event Timeout");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_TIMEOUT, mode, __LINE__);
				return IOT_ERROR_CONN_OPERATE_FAIL;
			}*/

		}
		/*str_len = strlen(conf->ssid);
		if(str_len) {
			memcpy(wifi_config.sta.ssid, conf->ssid, (str_len > IOT_WIFI_MAX_SSID_LEN) ? IOT_WIFI_MAX_SSID_LEN : str_len);
		}

		str_len = strlen(conf->pass);
		if(str_len) {
			memcpy(wifi_config.sta.password, conf->pass, (str_len > IOT_WIFI_MAX_PASS_LEN) ? IOT_WIFI_MAX_PASS_LEN : str_len);
		}*/

		wifi_config_t wifi_config = {
        	.sta = {
           		.ssid = EXAMPLE_ESP_WIFI_SSID,
            	.password = EXAMPLE_ESP_WIFI_PASS,
				//.bssid = {0x42,0x13,0x37,0x55,0xaa,0x01},
				//.threshold.authmode = WIFI_AUTH_WPA2_PSK,
				//.channel = 6
        	},
    	};

		IOT_INFO("target mac=%2X:%2X:%2X:%2X:%2X:%2X",
					wifi_config.sta.bssid[0], wifi_config.sta.bssid[1], wifi_config.sta.bssid[2],
					wifi_config.sta.bssid[3], wifi_config.sta.bssid[4], wifi_config.sta.bssid[5]);

		/*str_len = strlen((char *)conf->bssid);
		if(str_len) {
			memcpy(wifi_config.sta.bssid, conf->bssid, IOT_WIFI_MAX_BSSID_LEN);
			wifi_config.sta.bssid_set = true;

			IOT_DEBUG("target mac=%2X:%2X:%2X:%2X:%2X:%2X",
					wifi_config.sta.bssid[0], wifi_config.sta.bssid[1], wifi_config.sta.bssid[2],
					wifi_config.sta.bssid[3], wifi_config.sta.bssid[4], wifi_config.sta.bssid[5]);
		}*/

		/*if (conf->authmode == IOT_WIFI_AUTH_WPA3_PERSONAL) {
			wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA3_PSK;
			// set PMF (Protected Management Frames) optional mode for better compatibility
			wifi_config.sta.pmf_cfg.capable = true;
			wifi_config.sta.pmf_cfg.required = false;
		}*/
		//s_latest_disconnect_reason = IOT_ERROR_CONN_CONNECT_FAIL;

		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
		ESP_ERROR_CHECK(esp_wifi_start());

		IOT_INFO("connect to ap SSID:%s", wifi_config.sta.ssid);

		



		uxBits = xEventGroupWaitBits(wifi_event_group, WIFI_STA_CONNECT_BIT,
				true, false, IOT_WIFI_CMD_TIMEOUT);

		if((uxBits & WIFI_STA_CONNECT_BIT)) {
			IOT_INFO("AP Connected");
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_CONNECT_SUCCESS, 0, 0);
		}
		else {
			iot_error_t err = IOT_ERROR_CONN_CONNECT_FAIL;
			if (s_latest_disconnect_reason != IOT_ERROR_CONN_CONNECT_FAIL) {
				err = s_latest_disconnect_reason;
			}

			IOT_ERROR("WIFI_STA_CONNECT_BIT event Timeout %d", err);
			IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_CONNECT_FAIL, IOT_WIFI_CMD_TIMEOUT, err);
			return err;
		}

		time(&now);
		localtime_r(&now, &timeinfo);

		if (timeinfo.tm_year < (2016 - 1900)) {
			IOT_INFO("Time is not set yet. Connecting to WiFi and getting time over NTP.");
			_obtain_time();
		}

		break;

	default:
		IOT_ERROR("esp32c3 cannot support this mode = %d", conf->mode);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, conf->mode, __LINE__);
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	return IOT_ERROR_NONE;
}

uint16_t iot_bsp_wifi_get_scan_result(iot_wifi_scan_result_t *scan_result)
{
	uint16_t ap_num = 0;
	uint16_t i;
	wifi_scan_config_t config;
	wifi_ap_record_t *ap_list = NULL;

	memset(&config, 0x0, sizeof(config));

	esp_wifi_scan_start(&config, true);
	if(esp_wifi_scan_get_ap_num(&ap_num) == ESP_OK) {
		ap_num = (ap_num > IOT_WIFI_MAX_SCAN_RESULT) ?
				IOT_WIFI_MAX_SCAN_RESULT : ap_num;

		if(ap_num > 0) {
			ap_list = (wifi_ap_record_t *) malloc((ap_num+1) * sizeof(wifi_ap_record_t));
			if(!ap_list){
				IOT_ERROR("failed to malloc for wifi_ap_record_t");
				IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, 0, __LINE__);
				return 0;
			}
			/*need to initialize the scan buffer before updating*/
			memset(scan_result, 0x0, (IOT_WIFI_MAX_SCAN_RESULT * sizeof(iot_wifi_scan_result_t)));

			if(esp_wifi_scan_get_ap_records(&ap_num, ap_list) == ESP_OK){
				for(i=0; i<ap_num; i++)	{
					iot_wifi_auth_mode_t conv_auth_mode;

					switch (ap_list[i].authmode) {
#if (ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(4,3,0))
						case WIFI_AUTH_WAPI_PSK:
							conv_auth_mode = IOT_WIFI_AUTH_UNKNOWN;
							break;
#endif
						case WIFI_AUTH_WPA2_WPA3_PSK:
						case WIFI_AUTH_WPA3_PSK:
							conv_auth_mode = IOT_WIFI_AUTH_WPA3_PERSONAL;
							break;
						default:
							conv_auth_mode = ap_list[i].authmode;
							break;
					}
					memcpy(scan_result[i].ssid, ap_list[i].ssid, strlen((char *)ap_list[i].ssid));
					memcpy(scan_result[i].bssid, ap_list[i].bssid, IOT_WIFI_MAX_BSSID_LEN);

					scan_result[i].rssi = ap_list[i].rssi;
					scan_result[i].freq = iot_util_convert_channel_freq(ap_list[i].primary);
					scan_result[i].authmode = conv_auth_mode;

					IOT_DEBUG("scan result ssid=%s, mac=%02X:%02X:%02X:%02X:%02X:%02X, rssi=%d, freq=%d, authmode=%d chan=%d",
							scan_result[i].ssid,
							scan_result[i].bssid[0], scan_result[i].bssid[1], scan_result[i].bssid[2],
							scan_result[i].bssid[3], scan_result[i].bssid[4], scan_result[i].bssid[5], scan_result[i].rssi,
							scan_result[i].freq, scan_result[i].authmode, ap_list[i].primary);
				}
			}
			free(ap_list);
			memcpy(scan_result[ap_num].ssid, DUMMY_TARGET_WIFI_SSID, strlen(DUMMY_TARGET_WIFI_SSID));
			memcpy(scan_result[ap_num].bssid, DUMMY_TARGET_WIFI_BSSID , IOT_WIFI_MAX_BSSID_LEN);
			scan_result[ap_num].rssi = -39 ;
			scan_result[ap_num].freq = 2457 ;
			scan_result[ap_num].authmode = IOT_WIFI_AUTH_WPA2_PSK ;
			ap_num = ap_num +1;
		}
	} else {
		IOT_INFO("failed to get esp_wifi_scan_get_ap_num");
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, 0, __LINE__);
		ap_num = 0;
	}

	return ap_num;
}

iot_error_t iot_bsp_wifi_get_mac(struct iot_mac *wifi_mac)
{
	esp_err_t esp_ret;

	esp_ret = esp_wifi_get_mac(ESP_IF_WIFI_STA, wifi_mac->addr);
	if(esp_ret != ESP_OK){
		IOT_ERROR("failed to read wifi mac address : %d", esp_ret);
		IOT_DUMP(IOT_DEBUG_LEVEL_ERROR, IOT_DUMP_BSP_WIFI_ERROR, 0, __LINE__);
		return IOT_ERROR_CONN_OPERATE_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_wifi_freq_t iot_bsp_wifi_get_freq(void)
{
	return IOT_WIFI_FREQ_2_4G_ONLY;
}

iot_error_t iot_bsp_wifi_register_event_cb(iot_bsp_wifi_event_cb_t cb)
{
	if (cb == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}

	wifi_event_cb = cb;
	return IOT_ERROR_NONE;
}

void iot_bsp_wifi_clear_event_cb(void)
{
	wifi_event_cb = NULL;
}

iot_wifi_auth_mode_bits_t iot_bsp_wifi_get_auth_mode(void)
{
	iot_wifi_auth_mode_bits_t supported_mode_bits = IOT_WIFI_AUTH_MODE_BIT_ALL;
	supported_mode_bits ^= IOT_WIFI_AUTH_MODE_BIT(IOT_WIFI_AUTH_WPA2_ENTERPRISE);

	return supported_mode_bits;
}
