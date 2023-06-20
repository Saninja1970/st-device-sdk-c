	/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <esp_err.h>
#include <nvs_flash.h>
#include <esp_flash_encrypt.h>

#include "iot_bsp_fs.h"
#include "iot_bsp_nv_data.h"
#include "iot_debug.h"

#define STDK_NV_DATA_PARTITION "stnv"
#define STDK_NV_DATA_NAMESPACE "stdk"



static const char* _get_error_string(esp_err_t err) {

	switch(err) {
	case ESP_OK:
		return "Ok";
	case ESP_ERR_NVS_NO_FREE_PAGES:
		return "No Free Page";
	case ESP_ERR_NOT_FOUND:
		return "Partition Not Found";
	case ESP_ERR_NVS_NOT_INITIALIZED:
		return "NVS Not Initialized";
	case ESP_ERR_NVS_PART_NOT_FOUND:
		return "Partition Not Found";
	case ESP_ERR_NVS_NOT_FOUND:
		return "Namespace/Key Not Found";
	case ESP_ERR_NVS_INVALID_NAME:
		return "Namespace/Key Name Invalid";
	case ESP_ERR_NVS_INVALID_HANDLE:
		return "Invalid Handle";
	case ESP_ERR_NVS_INVALID_LENGTH:
		return "Invalid Length";
	case ESP_ERR_NVS_READ_ONLY:
		return "Read-only Handle";
	case ESP_ERR_NVS_NOT_ENOUGH_SPACE:
		return "Not Enough Space";
	case ESP_ERR_NVS_REMOVE_FAILED:
		return "Remove Failed";
	default:
		return "Unknown";
	}
}

#if defined(CONFIG_NVS_ENCRYPTION)
static iot_error_t _iot_bsp_fs_get_secure_config(nvs_sec_cfg_t *cfg)
{
	esp_err_t ret;
	const esp_partition_t *key_partition;

	if (!cfg) {
		return IOT_ERROR_INVALID_ARGS;
	}

	if (esp_flash_encryption_enabled()) {
		IOT_INFO("flash encryption is enabled");
	} else {
		IOT_ERROR("flash encryption is not enabled");
		return IOT_ERROR_FS_ENCRYPT_INIT;
	}

	key_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS_KEYS, NULL);
	if (!key_partition) {
		IOT_ERROR("nvs key partition not found");
		return IOT_ERROR_FS_ENCRYPT_INIT;
	}

	ret = nvs_flash_read_security_cfg(key_partition, cfg);
	if (ret == ESP_ERR_NVS_KEYS_NOT_INITIALIZED) {
		IOT_INFO("nvs key is empty");

		ret = nvs_flash_generate_keys(key_partition, cfg);
		if (ret != ESP_OK) {
			IOT_ERROR("failed to generate nvs key");
			return IOT_ERROR_FS_ENCRYPT_INIT;
		}

		IOT_INFO("nvs key is generated");
	}

	return IOT_ERROR_NONE;
}
#endif



#if 0

iot_error_t iot_bsp_fs_init()///////////////
{
	
	esp_err_t ret;
#if defined(CONFIG_NVS_ENCRYPTION)
	iot_error_t err;
	nvs_sec_cfg_t cfg;

	err = _iot_bsp_fs_get_secure_config(&cfg);
	IOT_WARN_CHECK(err != IOT_ERROR_NONE, IOT_ERROR_INIT_FAIL, "failed to get secure configuration");

	ret = nvs_flash_secure_init(&cfg);
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", NVS_DEFAULT_PART_NAME, _get_error_string(ret));

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	ret = nvs_flash_secure_init_partition(STDK_NV_DATA_PARTITION, &cfg);
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", STDK_NV_DATA_PARTITION, _get_error_string(ret));
#endif

#else /* !CONFIG_NVS_ENCRYPTION */

	ret = nvs_flash_init();
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", NVS_DEFAULT_PART_NAME, _get_error_string(ret));

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	ret = nvs_flash_init_partition(STDK_NV_DATA_PARTITION);
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", STDK_NV_DATA_PARTITION, _get_error_string(ret));
#endif
#endif /* CONFIG_NVS_ENCRYPTION */
	return IOT_ERROR_NONE;

	
	

}

iot_error_t iot_bsp_fs_deinit()
{
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	esp_err_t ret = nvs_flash_deinit_partition(STDK_NV_DATA_PARTITION);
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_DEINIT_FAIL, "nvs deinit failed [%s]", _get_error_string(ret));
#endif
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle)
{
	
	nvs_handle nvs_handle;
	nvs_open_mode nvs_open_mode;

	if (mode == FS_READONLY) {
		nvs_open_mode = NVS_READONLY;
		IOT_INFO("iot_bsp_fs_open NVS_READONLY");
	} else {
		nvs_open_mode = NVS_READWRITE;
		IOT_INFO("iot_bsp_fs_open NVS_READWRITE");
	}

	esp_err_t ret = nvs_open(STDK_NV_DATA_NAMESPACE, nvs_open_mode, &nvs_handle);
	if (ret == ESP_OK) {
		handle->fd = nvs_handle;
		snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
		return IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("nvs open failed [%s]", _get_error_string(ret));
		return IOT_ERROR_FS_OPEN_FAIL;
	}
	
}

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle)
{
	nvs_handle nvs_handle;
	nvs_open_mode nvs_open_mode = NVS_READONLY;

	esp_err_t ret = nvs_open_from_partition(STDK_NV_DATA_PARTITION, STDK_NV_DATA_NAMESPACE, nvs_open_mode, &nvs_handle);
	if (ret == ESP_OK) {
		handle->fd = nvs_handle;
		snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
		return IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("nv open failed [%s]", _get_error_string(ret));
		return IOT_ERROR_FS_OPEN_FAIL;
	}
}
#endif

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t *length)
{
	
	esp_err_t ret;
	size_t required_size;

	printf("[Simulator] iot_bsp_fs_read: enter\n");

	ret = nvs_get_str(handle.fd, handle.filename, NULL, &required_size);
	if (ret == ESP_ERR_NVS_NOT_FOUND) {
		IOT_ERROR("not found '%s'", handle.filename);
		return IOT_ERROR_FS_NO_FILE;
	} else if (ret != ESP_OK) {
		IOT_ERROR("nvs read failed [%s]", _get_error_string(ret));
		return IOT_ERROR_FS_READ_FAIL;
	}

	char* data = malloc(required_size);
	ret = nvs_get_str(handle.fd, handle.filename, data, &required_size);
	if (ret != ESP_OK) {
		IOT_ERROR("nvs read failed [%s]", _get_error_string(ret));
		free(data);
		return IOT_ERROR_FS_READ_FAIL;
	}

	if (*length < required_size) {
		IOT_ERROR("length is not enough (%d < %d)", *length, required_size);
		free(data);
		return IOT_ERROR_FS_READ_FAIL;
	} else {
		memcpy(buffer, data, required_size);
		*length = required_size;
	}

	free(data);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, unsigned int length)
{
	#if 0
	printf("[Simulator] iot_bsp_fs_write: enter\n");
	printf("[Simulator] iot_bsp_fs_write: data = %s\n",data);
	esp_err_t ret;

	ret = nvs_set_str(handle.fd, handle.filename, data);
	IOT_DEBUG_CHECK(ret != ESP_OK, IOT_ERROR_FS_WRITE_FAIL, "nvs write failed [%s]", _get_error_string(ret));

	if(ret == ESP_ERR_NVS_INVALID_HANDLE ){
		IOT_INFO("nvs write failed = ESP_ERR_NVS_INVALID_HANDLE  [%s]", _get_error_string(ret));
	}
	else if(ret == ESP_ERR_NVS_READ_ONLY){
		IOT_INFO("nvs write failed = ESP_ERR_NVS_READ_ONLY  [%s]", _get_error_string(ret));
	}
	else if(ret == ESP_ERR_NVS_INVALID_NAME ){
		IOT_INFO("nvs write failed = ESP_ERR_NVS_INVALID_NAME   [%s]", _get_error_string(ret));
	}
	else if(ret == ESP_ERR_NVS_NOT_ENOUGH_SPACE  ){
		IOT_INFO("nvs write failed = ESP_ERR_NVS_NOT_ENOUGH_SPACE    [%s]", _get_error_string(ret));
	}
	else if(ret == ESP_ERR_NVS_REMOVE_FAILED   ){
		IOT_INFO("nvs write failed = ESP_ERR_NVS_REMOVE_FAILED     [%s]", _get_error_string(ret));
	}
	else if(ret == ESP_ERR_NVS_VALUE_TOO_LONG    ){
		IOT_INFO("nvs write failed = ESP_ERR_NVS_VALUE_TOO_LONG      [%s]", _get_error_string(ret));
	}
	else{
		IOT_INFO("nvs write success [%s]", _get_error_string(ret));
	}

	ret = nvs_commit(handle.fd);
	if(ret!=ESP_OK){
		IOT_INFO("nvs_commit failed");
	}
	else{
		IOT_INFO("nvs_commit success");
	}

	return IOT_ERROR_NONE;

	#endif
	


}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	nvs_close(handle.fd);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{


	if (filename == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}

	nvs_handle nvs_handle;
	nvs_open_mode nvs_open_mode = NVS_READWRITE;

	esp_err_t ret = nvs_open(STDK_NV_DATA_NAMESPACE, nvs_open_mode, &nvs_handle);
	IOT_DEBUG_CHECK(ret != ESP_OK, IOT_ERROR_FS_REMOVE_FAIL, "nvs open failed [%s]", _get_error_string(ret));

	ret = nvs_erase_key(nvs_handle, filename);
	if (ret != ESP_OK) {
		IOT_DEBUG("nvs erase failed [%s]", _get_error_string(ret));
		nvs_close(nvs_handle);
		if (ret == ESP_ERR_NVS_NOT_FOUND) {
			return IOT_ERROR_FS_NO_FILE;
		} else {
			return IOT_ERROR_FS_REMOVE_FAIL;
		}
	}

	nvs_close(nvs_handle);
}

#else

//*********************************************************************
#define SIZE 30

typedef struct {
    char file_name[30];
    char content[100];
    unsigned int len;
} file;

file FILEE[SIZE];


////////////

void file_init(file *FILEE)
{
    for (int i = 0; i < SIZE; i++) 
    {
		
        strcpy(FILEE[i].file_name, "NULL");
        strcpy(FILEE[i].content, "NULL");
    }
}

iot_error_t write_file(char* name, const char* cont, unsigned int length) 
{
    int i=0;
	int j=-1;
	
    for (i = 0; i < SIZE; i++) 
    {
        if (strcmp(FILEE[i].file_name, "NULL") == 0) {
			j = i;
        }
		else if(strcmp(FILEE[i].file_name, name) == 0){
			break;
		}
    }

	if(i<SIZE){

		j = i;

	}

	if(j == -1){
		return IOT_ERROR_FS_WRITE_FAIL;
	}

	strcpy(FILEE[j].file_name, name);
    strcpy(FILEE[j].content, cont);
    FILEE[j].len = length;

	printf("[Simulator] write_file: file_name = %s , length = %d\n",FILEE[j].file_name,FILEE[j].len);


    return IOT_ERROR_NONE;
}

iot_error_t read_file(char* name, char* buffer, size_t* length) 
{

	printf("[Simulator] read_file: name = %s\n",name);

    for (int i = 0; i < SIZE; i++) 
    {
        
        
        if (strcmp(FILEE[i].file_name, name) == 0) 
        {
            memcpy(buffer, FILEE[i].content, FILEE[i].len);
			buffer[FILEE[i].len] = '\0';
            *length = FILEE[i].len;
			printf("[Simulator] read_file:file_name = %s ,length = %d\n",FILEE[i].file_name,FILEE[i].len);
            return IOT_ERROR_NONE;
        }
    }
    
    printf("File not found.\n");

	return IOT_ERROR_FS_NO_FILE;
}

iot_error_t empty_file(const char* name)
{   
    int i=0;
    for(i=0;i<SIZE;i++)
    {
        if(strcmp(FILEE[i].file_name , name) != 0)
        {
            continue;
        }
        else
        {
            if(strcmp(FILEE[i].file_name , "NULL") != 0)
            {
                strcpy(FILEE[i].file_name , "NULL");
                strcpy(FILEE[i].content , "NULL");
            }
			return IOT_ERROR_NONE;
        }
    }

	return IOT_ERROR_FS_NO_FILE;
    
}
//////////////


iot_error_t iot_bsp_fs_init()
{
	printf("[Simulator] iot_bsp_fs_init:enter\n");
	esp_err_t ret;

	ret = nvs_flash_init();
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", NVS_DEFAULT_PART_NAME, _get_error_string(ret));

    file_init(FILEE);
    return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle)
{

	printf("[Simulator] iot_bsp_fs_open:filename = %s\n",filename);
	snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle)
{
	/*nvs_handle nvs_handle;
	nvs_open_mode nvs_open_mode = NVS_READONLY;

	esp_err_t ret = nvs_open_from_partition(STDK_NV_DATA_PARTITION, STDK_NV_DATA_NAMESPACE, nvs_open_mode, &nvs_handle);
	if (ret == ESP_OK) {
		handle->fd = nvs_handle;
		snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
		return IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("nv open failed [%s]", _get_error_string(ret));
		return IOT_ERROR_FS_OPEN_FAIL;
	}*/
    return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t *length)
//iot_error_t iot_bsp_fs_read(HashTable* hashTable,char* buffer, const char* filename)
{
	return read_file(handle.filename,buffer,&length); 
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, unsigned int length)
//iot_error_t iot_bsp_fs_write(FileSystem* fileSystem, const char* filename, const char* content)
{

    return write_file(handle.filename, data,length); 

}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
//iot_error_t iot_bsp_fs_remove(FileSystem* fileSystem, const char* filename)
{
	
    return empty_file(filename);
}

iot_error_t iot_bsp_fs_deinit()
{
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	esp_err_t ret = nvs_flash_deinit_partition(STDK_NV_DATA_PARTITION);
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_DEINIT_FAIL, "nvs deinit failed [%s]", _get_error_string(ret));
#endif
	return IOT_ERROR_NONE;
}

#endif  