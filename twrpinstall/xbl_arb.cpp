//
// SPDX-FileCopyrightText: The LineageOS Project
// SPDX-License-Identifier: Apache-2.0
//

#include "xbl_arb.h"

#include <android-base/file.h>
#include <elf.h>
#include <string.h>
#include <unistd.h>

#include <optional>

namespace {

struct HeaderV6 {
	uint32_t image_id;
	uint32_t header_version;
	uint32_t qti_signature_size;
	uint32_t qti_cert_chain_size;
	uint32_t image_size;
	uint32_t code_size;
	uint32_t signature_ptr;
	uint32_t signature_size;
	uint32_t cert_chain_ptr;
	uint32_t cert_chain_size;
	uint32_t qti_metadata_size;
	uint32_t metadata_size;

	struct {
		uint32_t major_version;
		uint32_t minor_version;
		uint32_t software_id;
		uint32_t hardware_id;
		uint32_t oem_id;
		uint32_t model_id;
		uint32_t app_id;
		uint32_t flags;
		uint32_t soc_version[12];
		uint32_t multi_serial_numbers[8];
		uint32_t root_cert_index;
		uint32_t anti_rollback_version;
	} metadata;
};

struct HeaderV7 {
	uint32_t image_id;
	uint32_t header_version;
	uint32_t common_meta_size;
	uint32_t qti_metadata_size;
	uint32_t metadata_size;
	uint32_t code_size;
	uint32_t qti_signature_size;
	uint32_t qti_cert_chain_size;
	uint32_t signature_size;
	uint32_t cert_chain_size;

	struct {
		uint32_t major_version;
		uint32_t minor_version;
		uint32_t software_id;
		uint32_t app_id;
		uint32_t hash_table_algorithm;
		uint32_t measurement_register;
	} common_metadata;

	struct {
		uint32_t major_version;
		uint32_t minor_version;
		uint32_t anti_rollback_version;
		uint32_t root_cert_index;
		uint32_t soc_version[12];
		uint32_t feature_id;
		uint32_t hardware_id;
		uint64_t multi_serial_numbers[8];
		uint32_t oem_id;
		uint32_t model_id;
		uint64_t oem_lifecycle_state;
		uint32_t oem_root_cert_hash_algorithm;
		uint8_t oem_root_cert_hash[64];
		uint32_t flags;
	} metadata;
};

bool InRange(const std::string& buf, uint64_t off, uint64_t len) {
	return off <= buf.size() && len <= buf.size() - off;
}

std::optional<uint32_t> ReadAntiRollbackVersion(const std::string& path) {
	std::string buf;
	if (!android::base::ReadFileToString(path, &buf, true))
		return std::nullopt;

	if (!InRange(buf, 0, sizeof(Elf64_Ehdr)))
		return std::nullopt;
	Elf64_Ehdr eh;
	memcpy(&eh, buf.data(), sizeof(eh));
	if (memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64)
		return std::nullopt;

	for (int i = 0; i < eh.e_phnum; i++) {
		uint64_t ph_off = eh.e_phoff + (uint64_t)i * eh.e_phentsize;
		if (!InRange(buf, ph_off, sizeof(Elf64_Phdr)))
			return std::nullopt;
		Elf64_Phdr ph;
		memcpy(&ph, buf.data() + ph_off, sizeof(ph));
		if (ph.p_type != PT_NULL)
			continue;

		if (InRange(buf, ph.p_offset, sizeof(HeaderV6))) {
			HeaderV6 h6;
			memcpy(&h6, buf.data() + ph.p_offset, sizeof(h6));
			if (h6.header_version == 6 && h6.metadata_size == sizeof(HeaderV6::metadata))
				return h6.metadata.anti_rollback_version;
		}
		if (InRange(buf, ph.p_offset, sizeof(HeaderV7))) {
			HeaderV7 h7;
			memcpy(&h7, buf.data() + ph.p_offset, sizeof(h7));
			if (h7.header_version == 7 &&
			    h7.common_meta_size == sizeof(HeaderV7::common_metadata) &&
			    h7.metadata_size == sizeof(HeaderV7::metadata))
				return h7.metadata.anti_rollback_version;
		}
	}
	return std::nullopt;
}

std::string FindNode(const std::string& name) {
	static const char* kDirs[] = {"/dev/block/bootdevice/by-name/", "/dev/block/by-name/"};
	for (const char* d : kDirs) {
		std::string p = std::string(d) + name;
		if (access(p.c_str(), R_OK) == 0)
			return p;
	}
	return "";
}

}  // namespace

bool XblConfigArbAllowsSwitch(const std::string& booted_suffix, const std::string& target_suffix,
                              std::string* reason) {
	std::string booted_node = FindNode("xbl_config" + booted_suffix);
	std::string target_node = FindNode("xbl_config" + target_suffix);
	if (booted_node.empty() || target_node.empty())
		return true;

	auto booted = ReadAntiRollbackVersion(booted_node);
	if (!booted) {
		if (reason) *reason = "couldnt read the anti-rollback version of xbl_config + booted_suffix;
		return false;
	}
	auto target = ReadAntiRollbackVersion(target_node);
	if (!target) {
		if (reason) *reason = couldnt read the anti-rollback version of xbl_config" + target_suffix;
		return false;
	}
	if (*booted > *target) {
		if (reason)
			*reason = "xbl_config anti-rollback version would go down (" + std::to_string(*booted) +
			          " -> " + std::to_string(*target) + ")";
		return false;
	}
	return true;
}
