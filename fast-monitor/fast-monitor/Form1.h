#pragma once
#include <stdio.h>
#include <Windows.h>
#include "tchar.h"
#include <tlhelp32.h>
#include <detours.h>
#include <time.h>
#include <utility>
#include <string>
#include <vector>
#include <unordered_map>
#include <tuple>
#include <msclr\marshal_cppstd.h>
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable : 6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)
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

void init();
void exiting();
void vol(char* path, int op);

void imgui(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v);
static std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>>> detectionInfo;
static bool hooked = false;
extern std::string ghidraDirectory;

namespace CppCLRWinformsProjekt {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Runtime::InteropServices;

	/// <summary>
	/// Zusammenfassung f? Form1
	/// </summary>




	public ref class Form1 : public System::Windows::Forms::Form
	{
	public:
		Form1(void)
		{
			InitializeComponent();
			init();

			//
			//TODO: Konstruktorcode hier hinzuf?en.
			//
		}

	protected:
		/// <summary>
		/// Verwendete Ressourcen bereinigen.
		/// </summary>
		~Form1()
		{
			exiting();
			if (components)
			{
				delete components;
			}
		}

	private: System::Windows::Forms::TextBox^ logBox;

	private: System::Windows::Forms::ComboBox^ targetPID;
	private: System::Windows::Forms::MenuStrip^ menuStrip1;
	private: System::Windows::Forms::ToolStripMenuItem^ monitoringToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ startToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ stopToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ volatilityexeToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ browserawToolStripMenuItem;
	private: System::Windows::Forms::OpenFileDialog^ openFileDialog1;

	private: System::Windows::Forms::ListView^ api_list;
	private: System::Windows::Forms::ColumnHeader^ api_name;
	private: System::Windows::Forms::ColumnHeader^ addr;
	private: System::Windows::Forms::ColumnHeader^ size;
	private: System::Windows::Forms::ColumnHeader^ caller_pid;
	private: System::Windows::Forms::ListView^ detected;

	private: System::Windows::Forms::ColumnHeader^ callee_pid;
	private: System::Windows::Forms::ColumnHeader^ attack_num;
	private: System::Windows::Forms::ColumnHeader^ timestamp;
	private: System::Windows::Forms::ToolStripMenuItem^ ghidraToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ runGhidraToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ setGhidraPathToolStripMenuItem;
	private: System::Windows::Forms::ToolStripMenuItem^ yarascanToolStripMenuItem;

	protected:


	protected:


	private:
		/// <summary>
		/// Erforderliche Designervariable.
		/// </summary>
		System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Erforderliche Methode f? die Designerunterst?zung.
		/// Der Inhalt der Methode darf nicht mit dem Code-Editor ge?dert werden.
		/// </summary>
		void InitializeComponent(void)
		{
			this->logBox = (gcnew System::Windows::Forms::TextBox());
			this->targetPID = (gcnew System::Windows::Forms::ComboBox());
			this->menuStrip1 = (gcnew System::Windows::Forms::MenuStrip());
			this->monitoringToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->startToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->stopToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->volatilityexeToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->browserawToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->ghidraToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->setGhidraPathToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->runGhidraToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->openFileDialog1 = (gcnew System::Windows::Forms::OpenFileDialog());
			this->api_list = (gcnew System::Windows::Forms::ListView());
			this->caller_pid = (gcnew System::Windows::Forms::ColumnHeader());
			this->addr = (gcnew System::Windows::Forms::ColumnHeader());
			this->size = (gcnew System::Windows::Forms::ColumnHeader());
			this->api_name = (gcnew System::Windows::Forms::ColumnHeader());
			this->detected = (gcnew System::Windows::Forms::ListView());
			this->callee_pid = (gcnew System::Windows::Forms::ColumnHeader());
			this->attack_num = (gcnew System::Windows::Forms::ColumnHeader());
			this->timestamp = (gcnew System::Windows::Forms::ColumnHeader());
			this->yarascanToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->menuStrip1->SuspendLayout();
			this->SuspendLayout();
			// 
			// logBox
			// 
			this->logBox->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(35)), static_cast<System::Int32>(static_cast<System::Byte>(32)),
				static_cast<System::Int32>(static_cast<System::Byte>(39)));
			this->logBox->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;
			this->logBox->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->logBox->ForeColor = System::Drawing::Color::DarkGray;
			this->logBox->Location = System::Drawing::Point(5, 248);
			this->logBox->Margin = System::Windows::Forms::Padding(2);
			this->logBox->Multiline = true;
			this->logBox->Name = L"logBox";
			this->logBox->ReadOnly = true;
			this->logBox->ScrollBars = System::Windows::Forms::ScrollBars::Both;
			this->logBox->Size = System::Drawing::Size(771, 238);
			this->logBox->TabIndex = 2;
			// 
			// targetPID
			// 
			this->targetPID->Font = (gcnew System::Drawing::Font(L"±¼¸²", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->targetPID->FormattingEnabled = true;
			this->targetPID->Location = System::Drawing::Point(641, 4);
			this->targetPID->Margin = System::Windows::Forms::Padding(2);
			this->targetPID->Name = L"targetPID";
			this->targetPID->Size = System::Drawing::Size(133, 40);
			this->targetPID->TabIndex = 4;
			this->targetPID->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::targetPID_SelectedIndexChanged);
			// 
			// menuStrip1
			// 
			this->menuStrip1->AutoSize = false;
			this->menuStrip1->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(235)), static_cast<System::Int32>(static_cast<System::Byte>(42)),
				static_cast<System::Int32>(static_cast<System::Byte>(83)));
			this->menuStrip1->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->menuStrip1->GripMargin = System::Windows::Forms::Padding(2, 2, 0, 2);
			this->menuStrip1->ImageScalingSize = System::Drawing::Size(32, 32);
			this->menuStrip1->Items->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(3) {
				this->monitoringToolStripMenuItem,
					this->volatilityexeToolStripMenuItem, this->ghidraToolStripMenuItem
			});
			this->menuStrip1->Location = System::Drawing::Point(0, 0);
			this->menuStrip1->Name = L"menuStrip1";
			this->menuStrip1->Padding = System::Windows::Forms::Padding(5, 1, 0, 1);
			this->menuStrip1->Size = System::Drawing::Size(782, 33);
			this->menuStrip1->TabIndex = 5;
			this->menuStrip1->Text = L"menuStrip1";
			// 
			// monitoringToolStripMenuItem
			// 
			this->monitoringToolStripMenuItem->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(235)),
				static_cast<System::Int32>(static_cast<System::Byte>(42)), static_cast<System::Int32>(static_cast<System::Byte>(83)));
			this->monitoringToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->startToolStripMenuItem,
					this->stopToolStripMenuItem
			});
			this->monitoringToolStripMenuItem->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Bold));
			this->monitoringToolStripMenuItem->ForeColor = System::Drawing::Color::LightGray;
			this->monitoringToolStripMenuItem->Name = L"monitoringToolStripMenuItem";
			this->monitoringToolStripMenuItem->Size = System::Drawing::Size(169, 31);
			this->monitoringToolStripMenuItem->Text = L"Monitoring";
			// 
			// startToolStripMenuItem
			// 
			this->startToolStripMenuItem->Name = L"startToolStripMenuItem";
			this->startToolStripMenuItem->Size = System::Drawing::Size(218, 44);
			this->startToolStripMenuItem->Text = L"Start";
			this->startToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::startToolStripMenuItem_Click);
			// 
			// stopToolStripMenuItem
			// 
			this->stopToolStripMenuItem->Name = L"stopToolStripMenuItem";
			this->stopToolStripMenuItem->Size = System::Drawing::Size(218, 44);
			this->stopToolStripMenuItem->Text = L"Stop";
			this->stopToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::stopToolStripMenuItem_Click);
			// 
			// volatilityexeToolStripMenuItem
			// 
			this->volatilityexeToolStripMenuItem->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(235)),
				static_cast<System::Int32>(static_cast<System::Byte>(42)), static_cast<System::Int32>(static_cast<System::Byte>(83)));
			this->volatilityexeToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->browserawToolStripMenuItem,
					this->yarascanToolStripMenuItem
			});
			this->volatilityexeToolStripMenuItem->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Bold));
			this->volatilityexeToolStripMenuItem->ForeColor = System::Drawing::Color::LightGray;
			this->volatilityexeToolStripMenuItem->Name = L"volatilityexeToolStripMenuItem";
			this->volatilityexeToolStripMenuItem->Size = System::Drawing::Size(142, 31);
			this->volatilityexeToolStripMenuItem->Text = L"Volatility";
			// 
			// browserawToolStripMenuItem
			// 
			this->browserawToolStripMenuItem->Name = L"browserawToolStripMenuItem";
			this->browserawToolStripMenuItem->Size = System::Drawing::Size(359, 44);
			this->browserawToolStripMenuItem->Text = L"malfind";
			this->browserawToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::browserawToolStripMenuItem_Click);
			// 
			// ghidraToolStripMenuItem
			// 
			this->ghidraToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->setGhidraPathToolStripMenuItem,
					this->runGhidraToolStripMenuItem
			});
			this->ghidraToolStripMenuItem->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Bold));
			this->ghidraToolStripMenuItem->ForeColor = System::Drawing::Color::LightGray;
			this->ghidraToolStripMenuItem->Name = L"ghidraToolStripMenuItem";
			this->ghidraToolStripMenuItem->Size = System::Drawing::Size(118, 31);
			this->ghidraToolStripMenuItem->Text = L"Ghidra";
			// 
			// setGhidraPathToolStripMenuItem
			// 
			this->setGhidraPathToolStripMenuItem->Name = L"setGhidraPathToolStripMenuItem";
			this->setGhidraPathToolStripMenuItem->Size = System::Drawing::Size(543, 44);
			this->setGhidraPathToolStripMenuItem->Text = L"Set Ghidra Directory Path";
			this->setGhidraPathToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::setGhidraPathToolStripMenuItem_Click);
			// 
			// runGhidraToolStripMenuItem
			// 
			this->runGhidraToolStripMenuItem->Name = L"runGhidraToolStripMenuItem";
			this->runGhidraToolStripMenuItem->Size = System::Drawing::Size(543, 44);
			this->runGhidraToolStripMenuItem->Text = L"Run Ghidra and Open Project";
			this->runGhidraToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::runGhidraToolStripMenuItem_Click);
			// 
			// openFileDialog1
			// 
			this->openFileDialog1->FileName = L"openFileDialog1";
			// 
			// api_list
			// 
			this->api_list->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
				| System::Windows::Forms::AnchorStyles::Left)
				| System::Windows::Forms::AnchorStyles::Right));
			this->api_list->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(35)), static_cast<System::Int32>(static_cast<System::Byte>(32)),
				static_cast<System::Int32>(static_cast<System::Byte>(39)));
			this->api_list->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;
			this->api_list->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(4) {
				this->caller_pid, this->addr,
					this->size, this->api_name
			});
			this->api_list->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 9.75F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->api_list->ForeColor = System::Drawing::Color::White;
			this->api_list->HideSelection = false;
			this->api_list->Location = System::Drawing::Point(304, 35);
			this->api_list->Margin = System::Windows::Forms::Padding(2);
			this->api_list->Name = L"api_list";
			this->api_list->Size = System::Drawing::Size(472, 209);
			this->api_list->TabIndex = 7;
			this->api_list->UseCompatibleStateImageBehavior = false;
			this->api_list->View = System::Windows::Forms::View::Details;
			// 
			// caller_pid
			// 
			this->caller_pid->Text = L"Caller\'s PID";
			this->caller_pid->Width = 80;
			// 
			// addr
			// 
			this->addr->Text = L"address";
			this->addr->Width = 160;
			// 
			// size
			// 
			this->size->Text = L"size";
			this->size->Width = 58;
			// 
			// api_name
			// 
			this->api_name->Text = L"Windows API";
			this->api_name->Width = 174;
			// 
			// detected
			// 
			this->detected->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
				| System::Windows::Forms::AnchorStyles::Left)
				| System::Windows::Forms::AnchorStyles::Right));
			this->detected->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(35)), static_cast<System::Int32>(static_cast<System::Byte>(32)),
				static_cast<System::Int32>(static_cast<System::Byte>(39)));
			this->detected->BorderStyle = System::Windows::Forms::BorderStyle::FixedSingle;
			this->detected->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(3) {
				this->callee_pid, this->attack_num,
					this->timestamp
			});
			this->detected->Font = (gcnew System::Drawing::Font(L"µ¸¿ò", 10.125F, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->detected->ForeColor = System::Drawing::Color::White;
			this->detected->HideSelection = false;
			this->detected->Location = System::Drawing::Point(5, 35);
			this->detected->Margin = System::Windows::Forms::Padding(2);
			this->detected->Name = L"detected";
			this->detected->Size = System::Drawing::Size(295, 209);
			this->detected->TabIndex = 8;
			this->detected->UseCompatibleStateImageBehavior = false;
			this->detected->View = System::Windows::Forms::View::Details;
			this->detected->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::detected_SelectedIndexChanged);
			this->detected->MouseDoubleClick += gcnew System::Windows::Forms::MouseEventHandler(this, &Form1::detected_MouseDoubleClick);
			// 
			// callee_pid
			// 
			this->callee_pid->Text = L"PID";
			// 
			// attack_num
			// 
			this->attack_num->Text = L"attack#";
			// 
			// timestamp
			// 
			this->timestamp->Text = L"timestamp";
			this->timestamp->Width = 175;
			// 
			// yarascanToolStripMenuItem
			// 
			this->yarascanToolStripMenuItem->Name = L"yarascanToolStripMenuItem";
			this->yarascanToolStripMenuItem->Size = System::Drawing::Size(359, 44);
			this->yarascanToolStripMenuItem->Text = L"yarascan";
			this->yarascanToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::yarascanToolStripMenuItem_Click);
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(16, 27);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(11)), static_cast<System::Int32>(static_cast<System::Byte>(7)),
				static_cast<System::Int32>(static_cast<System::Byte>(17)));
			this->ClientSize = System::Drawing::Size(782, 490);
			this->Controls->Add(this->detected);
			this->Controls->Add(this->api_list);
			this->Controls->Add(this->targetPID);
			this->Controls->Add(this->logBox);
			this->Controls->Add(this->menuStrip1);
			this->Font = (gcnew System::Drawing::Font(L"±¼¸²", 10, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point, static_cast<System::Byte>(0)));
			this->ForeColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(235)), static_cast<System::Int32>(static_cast<System::Byte>(42)),
				static_cast<System::Int32>(static_cast<System::Byte>(83)));
			this->FormBorderStyle = System::Windows::Forms::FormBorderStyle::FixedSingle;
			this->MainMenuStrip = this->menuStrip1;
			this->Margin = System::Windows::Forms::Padding(2);
			this->MaximizeBox = false;
			this->Name = L"Form1";
			this->StartPosition = System::Windows::Forms::FormStartPosition::CenterScreen;
			this->Text = L"FAST-Monitor";
			this->Load += gcnew System::EventHandler(this, &Form1::Form1_Load);
			this->FormClosing += gcnew System::Windows::Forms::FormClosingEventHandler(this, &Form1::Form1_Closing);
			this->menuStrip1->ResumeLayout(false);
			this->menuStrip1->PerformLayout();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion

	public: Void logging(std::string buf) {
		String^ text = gcnew String(buf.c_str());
		String^ pid = (String^)(text->Split(' '))[0];
		if (this->targetPID->Items->Contains(pid) != true)
			this->targetPID->Items->Add(pid);
		this->logBox->AppendText(text);

	}


	public: Void show_detection(std::string callee_pid, std::vector< std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v) {

		System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(callee_pid.c_str()));
		item->SubItems->Add(gcnew String(std::get<3>(v[0]).ToString()));
		System::DateTime^ dt = gcnew System::DateTime();
		item->SubItems->Add(dt->Now.ToString("yyyy-MM-dd-HH-mm-ss"));

		this->detected->Items->Add(item);

		//###################
		detectionInfo.push_back(v);


	}


	private: System::Void targetPID_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {

		if (this->targetPID->SelectedIndex > -1) {

		}

	}
	private: System::Void Form1_Load(System::Object^ sender, System::EventArgs^ e) {
	}
	private: System::Void Form1_Closing(System::Object^ sender, System::Windows::Forms::FormClosingEventArgs^ e) {
		if (hooked) {
			Diagnostics::Process^ proc = Diagnostics::Process::Start("hook-dll.exe", "off");
			proc->WaitForExit();
		}
	}
	private: System::Void startToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Hook DLLs!\r\n\r\n");
		Diagnostics::Process^ proc = Diagnostics::Process::Start("hook-dll.exe", "on");
		proc->WaitForExit();
		hooked = true;
	}
	private: System::Void stopToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Unhook DLLs!\r\n\r\n");
		Diagnostics::Process^ proc = Diagnostics::Process::Start("hook-dll.exe", "off");
		proc->WaitForExit();
		hooked = false;
	}
	private: System::Void browserawToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {

		System::Windows::Forms::DialogResult dr = this->openFileDialog1->ShowDialog();

		if (System::Windows::Forms::DialogResult::OK == dr) {
			char* path = (char*)(void*)Marshal::StringToHGlobalAnsi(this->openFileDialog1->FileName);
			vol(path, 0);
			Marshal::FreeHGlobal((System::IntPtr)path);
		}
	}
	private: System::Void yarascanToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		System::Windows::Forms::DialogResult dr = this->openFileDialog1->ShowDialog();

		if (System::Windows::Forms::DialogResult::OK == dr) {
			char* path = (char*)(void*)Marshal::StringToHGlobalAnsi(this->openFileDialog1->FileName);
			vol(path, 1);
			Marshal::FreeHGlobal((System::IntPtr)path);
		}
	}

	private: System::Void detected_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {

		this->api_list->Items->Clear();

		std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v = detectionInfo.at(this->detected->FocusedItem->Index);

		for (auto tp : v) {
			mon_listing(tp);
		}
	}

	private: Void mon_listing(std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string> tp) {


		System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(std::get<2>(tp).c_str()));
		item->SubItems->Add(System::Convert::ToString((long long)std::get<0>(tp), 16));
		item->SubItems->Add(gcnew String(std::get<1>(tp).ToString()));
		item->SubItems->Add(gcnew String(getAPI(std::get<3>(tp)).c_str()));
		this->api_list->Items->Add(item);

	}

	private: System::Void setGhidraPathToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		Windows::Forms::FolderBrowserDialog^ dialog = gcnew Windows::Forms::FolderBrowserDialog();
		Windows::Forms::DialogResult result = dialog->ShowDialog();
		msclr::interop::marshal_context context;

		if (result == Windows::Forms::DialogResult::OK) {
			ghidraDirectory = context.marshal_as<std::string>(dialog->SelectedPath);
			this->logBox->AppendText("Set Ghidra directory: " + gcnew String(ghidraDirectory.c_str()) + "\r\n");
		}
	}

	private: System::Void runGhidraToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e);



	private: System::Void detected_MouseDoubleClick(System::Object^ sender, System::Windows::Forms::MouseEventArgs^ e) {
		std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR, std::string>> v = detectionInfo.at(this->detected->FocusedItem->Index);
		imgui(v);

	}

	private: std::string getAPI(UCHAR flags) {

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

		return std::string("");
	}

	};
}


