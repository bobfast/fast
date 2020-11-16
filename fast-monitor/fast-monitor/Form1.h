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


void init();
int mon(int isFree_);
void exiting();
void vol(char* path);

static std::vector<std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR>>> decectionInfo;

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
			this->ghidraToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->runGhidraToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->setGhidraPathToolStripMenuItem = (gcnew System::Windows::Forms::ToolStripMenuItem());
			this->menuStrip1->SuspendLayout();
			this->SuspendLayout();
			// 
			// logBox
			// 
			this->logBox->Location = System::Drawing::Point(6, 228);
			this->logBox->Margin = System::Windows::Forms::Padding(2, 2, 2, 2);
			this->logBox->Multiline = true;
			this->logBox->Name = L"logBox";
			this->logBox->ReadOnly = true;
			this->logBox->ScrollBars = System::Windows::Forms::ScrollBars::Both;
			this->logBox->Size = System::Drawing::Size(673, 214);
			this->logBox->TabIndex = 2;
			// 
			// targetPID
			// 
			this->targetPID->Font = (gcnew System::Drawing::Font(L"±¼¸²", 12, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->targetPID->FormattingEnabled = true;
			this->targetPID->Location = System::Drawing::Point(562, 28);
			this->targetPID->Margin = System::Windows::Forms::Padding(2, 2, 2, 2);
			this->targetPID->Name = L"targetPID";
			this->targetPID->Size = System::Drawing::Size(117, 24);
			this->targetPID->TabIndex = 4;
			this->targetPID->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::targetPID_SelectedIndexChanged);
			// 
			// menuStrip1
			// 
			this->menuStrip1->ImageScalingSize = System::Drawing::Size(32, 32);
			this->menuStrip1->Items->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(3) {
				this->monitoringToolStripMenuItem,
					this->volatilityexeToolStripMenuItem, this->ghidraToolStripMenuItem
			});
			this->menuStrip1->Location = System::Drawing::Point(0, 0);
			this->menuStrip1->Name = L"menuStrip1";
			this->menuStrip1->Padding = System::Windows::Forms::Padding(3, 1, 0, 1);
			this->menuStrip1->Size = System::Drawing::Size(684, 24);
			this->menuStrip1->TabIndex = 5;
			this->menuStrip1->Text = L"menuStrip1";
			// 
			// monitoringToolStripMenuItem
			// 
			this->monitoringToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->startToolStripMenuItem,
					this->stopToolStripMenuItem
			});
			this->monitoringToolStripMenuItem->Name = L"monitoringToolStripMenuItem";
			this->monitoringToolStripMenuItem->Size = System::Drawing::Size(79, 22);
			this->monitoringToolStripMenuItem->Text = L"Monitoring";
			// 
			// startToolStripMenuItem
			// 
			this->startToolStripMenuItem->Name = L"startToolStripMenuItem";
			this->startToolStripMenuItem->Size = System::Drawing::Size(99, 22);
			this->startToolStripMenuItem->Text = L"Start";
			this->startToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::startToolStripMenuItem_Click);
			// 
			// stopToolStripMenuItem
			// 
			this->stopToolStripMenuItem->Name = L"stopToolStripMenuItem";
			this->stopToolStripMenuItem->Size = System::Drawing::Size(99, 22);
			this->stopToolStripMenuItem->Text = L"Stop";
			this->stopToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::stopToolStripMenuItem_Click);
			// 
			// volatilityexeToolStripMenuItem
			// 
			this->volatilityexeToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(1) { this->browserawToolStripMenuItem });
			this->volatilityexeToolStripMenuItem->Name = L"volatilityexeToolStripMenuItem";
			this->volatilityexeToolStripMenuItem->Size = System::Drawing::Size(66, 22);
			this->volatilityexeToolStripMenuItem->Text = L"Volatility";
			// 
			// browserawToolStripMenuItem
			// 
			this->browserawToolStripMenuItem->Name = L"browserawToolStripMenuItem";
			this->browserawToolStripMenuItem->Size = System::Drawing::Size(138, 22);
			this->browserawToolStripMenuItem->Text = L"Browse .raw";
			this->browserawToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::browserawToolStripMenuItem_Click);
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
			this->api_list->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(4) {
				this->caller_pid, this->addr,
					this->size, this->api_name
			});
			this->api_list->GridLines = true;
			this->api_list->HideSelection = false;
			this->api_list->Location = System::Drawing::Point(262, 56);
			this->api_list->Margin = System::Windows::Forms::Padding(2, 2, 2, 2);
			this->api_list->Name = L"api_list";
			this->api_list->Size = System::Drawing::Size(417, 164);
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
			this->addr->Width = 120;
			// 
			// size
			// 
			this->size->Text = L"size";
			this->size->Width = 58;
			// 
			// api_name
			// 
			this->api_name->Text = L"Windows API";
			this->api_name->Width = 150;
			// 
			// detected
			// 
			this->detected->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
				| System::Windows::Forms::AnchorStyles::Left)
				| System::Windows::Forms::AnchorStyles::Right));
			this->detected->Columns->AddRange(gcnew cli::array< System::Windows::Forms::ColumnHeader^  >(3) {
				this->callee_pid, this->attack_num,
					this->timestamp
			});
			this->detected->Font = (gcnew System::Drawing::Font(L"±¼¸²", 9, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(129)));
			this->detected->HideSelection = false;
			this->detected->Location = System::Drawing::Point(7, 28);
			this->detected->Margin = System::Windows::Forms::Padding(2, 2, 2, 2);
			this->detected->Name = L"detected";
			this->detected->Size = System::Drawing::Size(245, 192);
			this->detected->TabIndex = 8;
			this->detected->UseCompatibleStateImageBehavior = false;
			this->detected->View = System::Windows::Forms::View::Details;
			this->detected->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::detected_SelectedIndexChanged);
			// 
			// callee_pid
			// 
			this->callee_pid->Text = L"PID";
			this->callee_pid->Width = 40;
			// 
			// attack_num
			// 
			this->attack_num->Text = L"attack#";
			// 
			// timestamp
			// 
			this->timestamp->Text = L"timestamp";
			this->timestamp->Width = 140;
			// 
			// ghidraToolStripMenuItem
			// 
			this->ghidraToolStripMenuItem->DropDownItems->AddRange(gcnew cli::array< System::Windows::Forms::ToolStripItem^  >(2) {
				this->runGhidraToolStripMenuItem,
					this->setGhidraPathToolStripMenuItem
			});
			this->ghidraToolStripMenuItem->Name = L"ghidraToolStripMenuItem";
			this->ghidraToolStripMenuItem->Size = System::Drawing::Size(54, 22);
			this->ghidraToolStripMenuItem->Text = L"Ghidra";
			// 
			// runGhidraToolStripMenuItem
			// 
			this->runGhidraToolStripMenuItem->Name = L"runGhidraToolStripMenuItem";
			this->runGhidraToolStripMenuItem->Size = System::Drawing::Size(180, 22);
			this->runGhidraToolStripMenuItem->Text = L"Run Ghidra";
			this->runGhidraToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::runGhidraToolStripMenuItem_Click);
			// 
			// setGhidraPathToolStripMenuItem
			// 
			this->setGhidraPathToolStripMenuItem->Name = L"setGhidraPathToolStripMenuItem";
			this->setGhidraPathToolStripMenuItem->Size = System::Drawing::Size(180, 22);
			this->setGhidraPathToolStripMenuItem->Text = L"Set Ghidra Path";
			this->setGhidraPathToolStripMenuItem->Click += gcnew System::EventHandler(this, &Form1::setGhidraPathToolStripMenuItem_Click);
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(7, 12);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(684, 452);
			this->Controls->Add(this->detected);
			this->Controls->Add(this->api_list);
			this->Controls->Add(this->targetPID);
			this->Controls->Add(this->logBox);
			this->Controls->Add(this->menuStrip1);
			this->MainMenuStrip = this->menuStrip1;
			this->Margin = System::Windows::Forms::Padding(2, 2, 2, 2);
			this->Name = L"Form1";
			this->Text = L"FAST-Monitor";
			this->Load += gcnew System::EventHandler(this, &Form1::Form1_Load);
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


	public: Void show_detection(std::string callee_pid, std::vector< std::tuple<DWORD64, DWORD, std::string, UCHAR>> v) {

		System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(callee_pid.c_str()));
		item->SubItems->Add(gcnew String(std::get<3>(v[0]).ToString()));
		System::DateTime^ dt = gcnew System::DateTime();
		item->SubItems->Add(dt->Now.ToString("yyyy-MM-dd-HH-mm-ss"));

		this->detected->Items->Add(item);

		//###################

		decectionInfo.push_back(v);
	}


	private: System::Void targetPID_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {

		if (this->targetPID->SelectedIndex > -1) {

		}

	}
	private: System::Void Form1_Load(System::Object^ sender, System::EventArgs^ e) {
	}
	private: System::Void startToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Hook DLLs!\r\n\r\n");
		mon(0);
	}
	private: System::Void stopToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		this->logBox->AppendText("Unhook DLLs!\r\n\r\n");
		mon(1);
	}
	private: System::Void browserawToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {

		System::Windows::Forms::DialogResult dr = this->openFileDialog1->ShowDialog();

		if (System::Windows::Forms::DialogResult::OK == dr) {
			char* path = (char*)(void*)Marshal::StringToHGlobalAnsi(this->openFileDialog1->FileName);
			vol(path);
			Marshal::FreeHGlobal((System::IntPtr)path);
		}
	}


	private: System::Void detected_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {

		this->api_list->Items->Clear();

		std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR>> v = decectionInfo.at(this->detected->FocusedItem->Index);



		if (std::get<3>(v[0]) & FLAG_VirtualAllocEx)
			listing_VirtualAllocEx(v);

		if (std::get<3>(v[0]) & FLAG_NtMapViewOfSection)
			listing_NtMapViewOfSection(v);

		if (std::get<3>(v[0]) & FLAG_VirtualProtectEx)
			listing_VirtualProtectEx(v);

		if (std::get<3>(v[0]) & FLAG_CreateRemoteThread)
			listing_CreateRemoteThread(v);

		if (std::get<3>(v[0]) & FLAG_SetWindowLongPtrA)
			listing_SetWindowLongPtr(v);

		if (std::get<3>(v[0]) & FLAG_SetPropA)
			listing_SetPropA(v);

		if (std::get<3>(v[0]) & FLAG_SetThreadContext)
			;

		if (std::get<3>(v[0]) & FLAG_NtQueueApcThread)
			;
	}

	private: Void listing_VirtualAllocEx(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR>> v) {


		System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(std::get<2>(v[0]).c_str()));
		item->SubItems->Add(System::Convert::ToString((long long)std::get<0>(v[0]), 16));
		item->SubItems->Add(gcnew String(std::get<1>(v[0]).ToString()));
		item->SubItems->Add(gcnew String("VirtualAllocEx"));
		this->api_list->Items->Add(item);

	}

	private: Void listing_NtMapViewOfSection(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR>> v) {


		System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(std::get<2>(v[0]).c_str()));
		item->SubItems->Add(System::Convert::ToString((long long)std::get<0>(v[0]), 16));
		item->SubItems->Add(gcnew String(std::get<1>(v[0]).ToString()));
		item->SubItems->Add(gcnew String("NtMapViewOfSection"));
		this->api_list->Items->Add(item);

	}

	private: Void listing_VirtualProtectEx(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR>> v) {


		System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(std::get<2>(v[0]).c_str()));
		item->SubItems->Add(System::Convert::ToString((long long)std::get<0>(v[0]), 16));
		item->SubItems->Add(gcnew String(std::get<1>(v[0]).ToString()));
		item->SubItems->Add(gcnew String("VirtualProtectEx"));
		this->api_list->Items->Add(item);

	}

	private: Void listing_CreateRemoteThread(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR>> v) {
		for (auto tp : v) {
			if (std::get<3>(tp) == FLAG_CreateRemoteThread) {
				System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(std::get<2>(tp).c_str()));
				item->SubItems->Add(System::Convert::ToString((long long)std::get<0>(tp), 16));
				item->SubItems->Add(gcnew String(""));
				item->SubItems->Add(gcnew String("CreateRemoteThread"));
				this->api_list->Items->Add(item);
			}
		}
	}

	private: Void listing_SetWindowLongPtr(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR>> v) {
		for (auto tp : v) {
			if (std::get<3>(tp) == FLAG_SetWindowLongPtrA) {
				System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(std::get<2>(tp).c_str()));
				item->SubItems->Add(System::Convert::ToString((long long)std::get<0>(tp), 16));
				item->SubItems->Add(gcnew String(""));
				item->SubItems->Add(gcnew String("SetWindowLongPtr"));
				this->api_list->Items->Add(item);
			}
		}
	}

	private: Void listing_SetPropA(std::vector<std::tuple<DWORD64, DWORD, std::string, UCHAR>> v) {
		for (auto tp : v) {
			if (std::get<3>(tp) == FLAG_SetPropA) {
				System::Windows::Forms::ListViewItem^ item = gcnew System::Windows::Forms::ListViewItem(gcnew String(std::get<2>(tp).c_str()));
				item->SubItems->Add(System::Convert::ToString((long long)std::get<0>(tp), 16));
				item->SubItems->Add(gcnew String(""));
				item->SubItems->Add(gcnew String("SetPropA"));
				this->api_list->Items->Add(item);
			}
		}
	}


	private: System::Void runGhidraToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
		if (!IO::File::Exists("GhidraMemdmpProject.gpr")) {
			MessageBox::Show("There is no ghidra project for dumpfiles. (not detected yet...)", "Running Ghidra Failed!", MessageBoxButtons::OK, MessageBoxIcon::Error);
			return;
		}

		Diagnostics::Process::Start("D:\\ProgramForResearch\\ghidra_9.1.2_PUBLIC\\ghidraRun.bat", IO::Path::GetFullPath("GhidraMemdmpProject.gpr"));
	}

	private: System::Void setGhidraPathToolStripMenuItem_Click(System::Object^ sender, System::EventArgs^ e) {
	}
};

}


