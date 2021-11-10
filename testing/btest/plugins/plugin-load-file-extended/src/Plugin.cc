
#include "Plugin.h"

namespace btest::plugin::Testing_LoadFileExtended
	{
Plugin plugin;
	}

using namespace btest::plugin::Testing_LoadFileExtended;

zeek::plugin::Configuration Plugin::Configure()
	{
	EnableHook(zeek::plugin::HOOK_LOAD_FILE_EXT);

	zeek::plugin::Configuration config;
	config.name = "Testing::LoadFileExtended";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 4;
	return config;
	}

#include <iostream>

std::pair<int, std::optional<std::string>> Plugin::HookLoadFileExtended(const LoadType type,
                                                                        const std::string& file,
                                                                        const std::string& resolved)
	{
	if ( type == LoadType::SCRIPT && file == "xxx" )
		{
		printf("HookLoadExtended/script: file=|%s| resolved=|%s|\n", file.c_str(), resolved.c_str());

		return std::make_pair(1, R"(
			event zeek_init() {
				print "new zeek_init(): script has been replaced";
			}

			event signature_match(state: signature_state, msg: string, data: string) {
				print msg;
			}
		)");
		}

	if ( type == LoadType::SCRIPT && file == "yyy" )
		{
		printf("HookLoadExtended/script: file=|%s| resolved=|%s|\n", file.c_str(), resolved.c_str());

		return std::make_pair(1, R"(
			event zeek_init() {
				print "new zeek_init(): script has been added";
			}
		)");
		}

	if ( type == LoadType::SIGNATURES && file == "abc.sig" )
		{
		printf("HookLoadExtended/signature: file=|%s| resolved=|%s|\n", file.c_str(), resolved.c_str());

		return std::make_pair(1, R"(
		signature my-sig {
			ip-proto == tcp
			payload /GET \/images/
			event "signature works!"
			}
		)");
		}

	return std::make_pair(-1, std::nullopt);
	}

