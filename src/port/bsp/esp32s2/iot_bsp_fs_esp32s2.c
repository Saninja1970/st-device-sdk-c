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
#define MAX_FILENAME_LENGTH 100
#define MAX_FILE_CONTENT_LENGTH 100
#define HASH_TABLE_SIZE 30
//char buffer1[MAX_FILE_CONTENT_LENGTH]; 

typedef struct {
    char filename[MAX_FILENAME_LENGTH];
    char content[MAX_FILE_CONTENT_LENGTH];
	unsigned int content_length;
} File;

typedef struct {
    File files[HASH_TABLE_SIZE];
} HashTable;

HashTable hashTable;


unsigned int hash(const char* filename) {
    unsigned int hash = 0;
    for (int i = 0; filename[i] != '\0'; i++) {
        hash = hash * 31 + filename[i];
    }
    return hash % HASH_TABLE_SIZE;
}

void insertFile(HashTable* hashTable, const char* filename, const char* content,unsigned int length) {
    unsigned int index = hash(filename);

    strncpy(hashTable->files[index].filename, filename, MAX_FILENAME_LENGTH);
    memcpy(hashTable->files[index].content, content, length);
	hashTable->files[index].content_length = length;
}

// const char* getFileContent(HashTable* hashTable, const char* filename) {
//     unsigned int index = hash(filename);
//     while (strcmp(hashTable->files[index].filename, filename) != 0) {
//         index = (index + 1) % HASH_TABLE_SIZE;
//         if (hashTable->files[index].filename[0] == '\0') {
//             return NULL;  // File not found
//         }
//     }
//     return hashTable->files[index].content;
// }

void readFile(HashTable* hashTable, const char* filename,char *value,size_t *length) {
    unsigned int index = hash(filename);

	printf("[Simulator] readFile: enter\n");

	printf("[Simulator] readFile: index = %d\n",index);

    while (strcmp(hashTable->files[index].filename, filename) != 0) {
        index = (index + 1) % HASH_TABLE_SIZE;
        if (hashTable->files[index].filename[0] == '\0') {
            value[0] = '\0';  // Set buffer to an empty string
            return;  // File not found
        }
    }

	

    memcpy(value, hashTable->files[index].content, hashTable->files[index].content_length);

	printf("[Simulator] readFile:value = %s\n",value);
	
    value[hashTable->files[index].content_length] = '\0';  // Ensure buffer is null-terminated
	*length = hashTable->files[index].content_length;

	printf("[Simulator] readFile:length = %n\n",length);


}
void deleteFile(HashTable* hashTable, const char* filename) {
    unsigned int index = hash(filename);
    while (strcmp(hashTable->files[index].filename, filename) != 0) {
        index = (index + 1) % HASH_TABLE_SIZE;
        if (hashTable->files[index].filename[0] == '\0') {
            return; 
        }
    }
    hashTable->files[index].filename[0] = '\0';  // Mark the slot as empty
}

/*typedef struct {
    HashTable* hashTable;
} FileSystem;
*/
//FileSystem fileSystem;

//88888888888888888888888888888888888888888888888888888888888888
//no parameters are being passed
iot_error_t iot_bsp_fs_init()
{
	printf("[Simulator] iot_bsp_fs_init:enter\n");

	esp_err_t ret;

	ret = nvs_flash_init();
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", NVS_DEFAULT_PART_NAME, _get_error_string(ret));

	memset(&hashTable, 0, sizeof(HashTable));
    return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle)
{

	printf("[Simulator] iot_bsp_fs_open:filename = %s\n",filename);
	snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
	printf("[Simulator] iot_bsp_fs_open:handle->filename = %s\n",handle->filename);
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
	//return getFileContent(&fileSystem->hashTable, filename);

	// unsigned int index = hash(filename);
    // while (strcmp(hashTable->files[index].filename, filename) != 0) {
    //     index = (index + 1) % HASH_TABLE_SIZE;
    //     if (hashTable->files[index].filename[0] == '\0') {
    //         return NULL;  // File not found
    //     }
    // }

    // size_t contentLength = strlen(hashTable->files[index].content);
    // char* buffer = malloc((contentLength + 1) * sizeof(char));
    // if (buffer != NULL) {
    //     strncpy(buffer, hashTable->files[index].content, contentLength);
    //     buffer[contentLength] = '\0';
    // }
	/* unsigned int index = hash(filename);
   	 while (strcmp(hashTable->files[index].filename, filename) != 0) {
        index = (index + 1) % HASH_TABLE_SIZE;
        if (hashTable->files[index].filename[0] == '\0') {
            buffer[0] = '\0';  // Set buffer to an empty string
            return IOT_ERROR_FS_OPEN_FAIL;  // File not found
        }*/
        readFile(&hashTable,handle.filename,buffer,length);

		printf("[Simulator] iot_bsp_fs_read: buffer = %s\n",buffer);
		printf("[Simulator] iot_bsp_fs_read: handle.filename = %s\n",handle.filename);
		printf("[Simulator] iot_bsp_fs_read: length = %n\n",length);


        return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, unsigned int length)
//iot_error_t iot_bsp_fs_write(FileSystem* fileSystem, const char* filename, const char* content)
{

	printf("[Simulator] iot_bsp_fs_write: data = %s\n",data);
	printf("[Simulator] iot_bsp_fs_write: handle.filename = %s\n",handle.filename);
	printf("[Simulator] iot_bsp_fs_write: length = %d\n",length);



	 insertFile(&hashTable, handle.filename, data,length);
	 return IOT_ERROR_NONE;

}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
//iot_error_t iot_bsp_fs_remove(FileSystem* fileSystem, const char* filename)
{
	deleteFile(&hashTable, filename);
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

#endif