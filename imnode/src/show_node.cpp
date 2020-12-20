#include "node_editor.h"
#include <imnodes.h>
#include <imgui.h>
#include <vector>
#include <string>
#include <tuple>
/// <summary>
/// flags
/// </summary>

#define FLAG_VirtualAllocEx 0b00000001
#define FLAG_NtMapViewOfSection 0b00000010
#define FLAG_VirtualProtectEx  0b00000100
#define FLAG_CreateRemoteThread 0b00001000
#define FLAG_SetWindowLongPtrA 0b00010000  
#define FLAG_SetPropA 0b00100000
#define FLAG_SetThreadContext 0b01000000
#define FLAG_NtQueueApcThread 0b10000000 
#define FLAG_WriteProcessMemory 0b10000000 



namespace Show_node
{
    namespace
    {
        class NodeEditor
        {

        public:
            bool callstack_view[3] = { false, false, false };

            std::string getAPI(UCHAR flags) {

                if (flags & FLAG_VirtualAllocEx)
                    return std::string("VirtualAllocEx");
                if (flags & FLAG_NtMapViewOfSection)
                    return std::string("NtMapViewOfSection");
                if (flags & FLAG_VirtualProtectEx)
                    return std::string("VirtualProtectEx");

                if (flags == FLAG_WriteProcessMemory)
                    return std::string("WriteProcessMemory");


                if (flags == FLAG_CreateRemoteThread)
                    return std::string("CreateRemoteThread");
                if (flags == FLAG_SetWindowLongPtrA)
                    return std::string("SetWindowLongPtrA");
                if (flags == FLAG_SetPropA)
                    return std::string("SetPropA");
                if (flags == FLAG_SetThreadContext)
                    return std::string("SetThreadContext");

            }

            void listing(int current, int attribute, int index, std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string, std::string> tp) {
                if (current == 1) {
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBar, IM_COL32(37, 142, 63, 255));
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBarSelected, IM_COL32(71, 209, 71, 255));
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBarHovered, IM_COL32(71, 209, 71, 255));
                }
                else if (current == index) {
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBar, IM_COL32(230, 0, 0, 255));
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBarSelected, IM_COL32(255, 51, 51, 255));
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBarHovered, IM_COL32(255, 51, 51, 255));
                }
                else {
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBar, IM_COL32(230, 115, 0, 255));
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBarSelected, IM_COL32(255, 128, 0, 255));
                    imnodes::PushColorStyle(
                        imnodes::ColorStyle_TitleBarHovered, IM_COL32(255, 128, 0, 255));
                }
                imnodes::BeginNode(current);
                imnodes::BeginNodeTitleBar();
                ImGui::TextUnformatted(getAPI(std::get<3>(tp)).c_str());
                imnodes::EndNodeTitleBar();
                if (current != 1)
                {
                    imnodes::BeginInputAttribute(attribute); //ex attribute 2
                    imnodes::EndInputAttribute();
                }
                ImGui::BulletText("CALLER PID    : %s", std::get<2>(tp).c_str());
                ImGui::BulletText("START ADDRESS : %016llx", std::get<0>(tp));
                if (std::get<1>(tp) > 0) {
                    ImGui::BulletText("END ADDRESS   : %016llx", std::get<0>(tp) + std::get<1>(tp));
                    ImGui::BulletText("SIZE          : %d", std::get<1>(tp));
                }
                ImGui::BulletText("CALLER's PATH : %s", std::get<4>(tp).c_str());
                if (current != index) {
                    imnodes::BeginOutputAttribute(attribute + 1); // ex attribute 3
                    imnodes::EndOutputAttribute();
                }

                char buf[256];
                sprintf_s(buf, 256, "View Callstack of '%s()'", getAPI(std::get<3>(tp)).c_str());

                if (ImGui::Button(buf))
                    if (callstack_view[current] == false)
                        callstack_view[current] = true;
                    else
                        callstack_view[current] = false;

                imnodes::EndNode();
                imnodes::PopColorStyle();
                imnodes::PopColorStyle();
                imnodes::PopColorStyle();
                if (callstack_view[current])
                {
                    ImGui::Begin(buf, &callstack_view[current]);   // Pass a pointer to our bool variable (the window will have a closing button that will clear the bool when clicked)
                    ImGui::Text("%s call stack :\n%s", getAPI(std::get<3>(tp)).c_str(), std::get<5>(tp).c_str());
                    ImGui::End();
                }
            }

            void show(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string, std::string>> v)
            {
                int index = v.size(); //
                int current = 1; //
                int attribute = 2;
                std::vector<std::pair<int, int>> links;
                ImGui::Begin("Attack Flow");
                imnodes::BeginNodeEditor();

                for (auto tp : v) {
                    listing(current, attribute, index, tp);
                    current++;
                    attribute += 3;
                }

                //connect links
                for (int i = 1; i < index; i++) {
                    links.push_back(std::make_pair(3 * i, 3 * i + 2));
                }
                // elsewhere in the code...
                for (int i = 0; i < links.size(); ++i)
                {
                    const std::pair<int, int> p = links[i];
                    imnodes::Link(i, p.first, p.second);
                }
                //

                imnodes::EndNodeEditor();

                ImGui::End();


            }
        };

        static NodeEditor editor;
    }

    void NodeEditorInitialize(unsigned int vsize) {
        for (int i = 1; i < vsize + 1; i++) {
            imnodes::SetNodeGridSpacePos(i, ImVec2(200.0f * (i - 1), 200.0f * (i - 1)));
        }
    }

    void NodeEditorShow(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string, std::string>> v) { editor.show(v); }

    void NodeEditorShutdown() {}

}