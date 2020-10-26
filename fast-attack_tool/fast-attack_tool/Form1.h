#pragma once



void attack(unsigned int pid, unsigned int tid, int method);


namespace CppCLRWinformsProjekt {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;

	/// <summary>
	/// Zusammenfassung f? Form1
	/// </summary>
	public ref class Form1 : public System::Windows::Forms::Form
	{
	public:
		Form1(void)
		{
			InitializeComponent();
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
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Button^ attack_button;
	private: System::Windows::Forms::TextBox^ pid_input;
	private: System::Windows::Forms::TextBox^ tid_input;
	private: System::Windows::Forms::Label^ pid_label;
	private: System::Windows::Forms::Label^ tid_label;
	private: System::Windows::Forms::ComboBox^ options;
	private: System::Windows::Forms::Label^ option_label;
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
			this->attack_button = (gcnew System::Windows::Forms::Button());
			this->pid_input = (gcnew System::Windows::Forms::TextBox());
			this->tid_input = (gcnew System::Windows::Forms::TextBox());
			this->pid_label = (gcnew System::Windows::Forms::Label());
			this->tid_label = (gcnew System::Windows::Forms::Label());
			this->options = (gcnew System::Windows::Forms::ComboBox());
			this->option_label = (gcnew System::Windows::Forms::Label());
			this->SuspendLayout();
			// 
			// attack_button
			// 
			this->attack_button->Location = System::Drawing::Point(707, 39);
			this->attack_button->Name = L"attack_button";
			this->attack_button->Size = System::Drawing::Size(194, 102);
			this->attack_button->TabIndex = 0;
			this->attack_button->Text = L"Attack";
			this->attack_button->UseVisualStyleBackColor = true;
			this->attack_button->Click += gcnew System::EventHandler(this, &Form1::attack_button_Click);
			// 
			// pid_input
			// 
			this->pid_input->Location = System::Drawing::Point(32, 89);
			this->pid_input->Name = L"pid_input";
			this->pid_input->Size = System::Drawing::Size(153, 35);
			this->pid_input->TabIndex = 1;
			this->pid_input->Text = L"0";
			this->pid_input->TextChanged += gcnew System::EventHandler(this, &Form1::pid_input_TextChanged);
			// 
			// tid_input
			// 
			this->tid_input->Location = System::Drawing::Point(256, 89);
			this->tid_input->Name = L"tid_input";
			this->tid_input->Size = System::Drawing::Size(157, 35);
			this->tid_input->TabIndex = 2;
			this->tid_input->Text = L"0";
			this->tid_input->TextChanged += gcnew System::EventHandler(this, &Form1::tid_input_TextChanged);
			// 
			// pid_label
			// 
			this->pid_label->AutoSize = true;
			this->pid_label->Location = System::Drawing::Point(28, 39);
			this->pid_label->Name = L"pid_label";
			this->pid_label->Size = System::Drawing::Size(118, 24);
			this->pid_label->TabIndex = 3;
			this->pid_label->Text = L"Target PID";
			// 
			// tid_label
			// 
			this->tid_label->AutoSize = true;
			this->tid_label->Location = System::Drawing::Point(252, 39);
			this->tid_label->Name = L"tid_label";
			this->tid_label->Size = System::Drawing::Size(117, 24);
			this->tid_label->TabIndex = 4;
			this->tid_label->Text = L"Target TID";
			// 
			// options
			// 
			this->options->FormattingEnabled = true;
			this->options->Items->AddRange(gcnew cli::array< System::Object^  >(2) {
				L"#1 : it uses CreateRemoteThread, VirtualAllocEx and WriteProcessMemory.",
					L"#2 : it uses CreateRemoteThread, CreateFileMappingA, MapViewOfFile and PNtMapView"
					L"OfSection."
			});
			this->options->Location = System::Drawing::Point(32, 234);
			this->options->Name = L"options";
			this->options->Size = System::Drawing::Size(869, 32);
			this->options->TabIndex = 5;
			this->options->SelectedIndexChanged += gcnew System::EventHandler(this, &Form1::options_SelectedIndexChanged);
			// 
			// option_label
			// 
			this->option_label->AutoSize = true;
			this->option_label->Location = System::Drawing::Point(28, 170);
			this->option_label->Name = L"option_label";
			this->option_label->Size = System::Drawing::Size(78, 24);
			this->option_label->TabIndex = 6;
			this->option_label->Text = L"Option";
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(13, 24);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(942, 315);
			this->Controls->Add(this->option_label);
			this->Controls->Add(this->options);
			this->Controls->Add(this->tid_label);
			this->Controls->Add(this->pid_label);
			this->Controls->Add(this->tid_input);
			this->Controls->Add(this->pid_input);
			this->Controls->Add(this->attack_button);
			this->Name = L"Form1";
			this->Text = L"fast-attack_tool";
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion
	private: System::Void attack_button_Click(System::Object^ sender, System::EventArgs^ e) {
		attack(UInt32::Parse(this->pid_input->Text), UInt32::Parse(this->tid_input->Text), this->options->SelectedIndex + 1);
	}
	private: System::Void pid_input_TextChanged(System::Object^ sender, System::EventArgs^ e) {

	}
	private: System::Void tid_input_TextChanged(System::Object^ sender, System::EventArgs^ e) {

	}
	private: System::Void options_SelectedIndexChanged(System::Object^ sender, System::EventArgs^ e) {


	}
};
}
