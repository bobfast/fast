#include "node_editor.h"
#include <imnodes.h>
#include <imgui.h>
#include <vector>
#include <string>
#include <tuple>
//#include "../../fast-monitor/fast-monitor/Form1.h"
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


#define indexof( datum, data ) ( &datum - &*data.begin() )


namespace Show_node
{
    namespace
    {
        class NodeEditor
        {

        public:
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

            }

            void listing(int current, int attribute, unsigned int idx,  std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string> tp) {
                imnodes::BeginNode(current);
                imnodes::BeginNodeTitleBar();
                ImGui::TextUnformatted(getAPI(std::get<3>(tp)).c_str());
                imnodes::EndNodeTitleBar();
                imnodes::BeginInputAttribute(attribute); //ex attribute 2
                imnodes::EndInputAttribute();
                imnodes::BeginOutputAttribute(attribute+1); // ex attribute 3
                ImGui::BulletText("CALLER PID    : %s", std::get<2>(tp).c_str());
                ImGui::BulletText("START ADDRESS : %016llx", std::get<0>(tp));
                if (std::get<1>(tp)>0) {
                    ImGui::BulletText("END ADDRESS   : %016llx", std::get<0>(tp) + std::get<1>(tp));
                    ImGui::BulletText("SIZE          : %d", std::get<1>(tp));
                }
                ImGui::BulletText("CALLER's PATH : %s", std::get<4>(tp).c_str());
                imnodes::EndOutputAttribute();
                imnodes::EndNode();
            }
      
            void show(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v)
            {
                int index = v.size(); //생성할 노드의 총 개수 
                int current = 1; //노드 추가 시 current 증가
                int attribute = 2;
                std::vector<std::pair<int, int>> links;
                ImGui::Begin("Attack Flow");
                imnodes::BeginNodeEditor();

                for (auto tp : v) {
                    listing(current, attribute, indexof(tp, v) , tp );
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
        for (int i = 1; i < vsize +1 ; i++) {
            imnodes::SetNodeGridSpacePos(i, ImVec2( 200.0f * (i-1),  200.0f * (i-1)));
        }
    }

    void NodeEditorShow(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v) { editor.show(v); }

    void NodeEditorShutdown() {}

} 