#pragma once
#include <Windows.h>
#include <string>
#include <vector>
namespace Show_node
{
void NodeEditorInitialize(unsigned int vsize);
void NodeEditorShow(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string, std::string>> v);
void NodeEditorShutdown();

} // namespace example