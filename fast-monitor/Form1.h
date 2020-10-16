#pragma once

void init();
int mon(int isFree_);


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
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Button^ hookAndMonitoring;
	private: System::Windows::Forms::Button^ unhook;
	private: System::Windows::Forms::TextBox^ logBox;
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
			

			this->hookAndMonitoring = (gcnew System::Windows::Forms::Button());
			this->unhook = (gcnew System::Windows::Forms::Button());
			this->logBox = (gcnew System::Windows::Forms::TextBox());
			this->SuspendLayout();
			// 
			// hookAndMonitoring
			// 
			this->hookAndMonitoring->Location = System::Drawing::Point(55, 77);
			this->hookAndMonitoring->Name = L"hookAndMonitoring";
			this->hookAndMonitoring->Size = System::Drawing::Size(242, 82);
			this->hookAndMonitoring->TabIndex = 0;
			this->hookAndMonitoring->Text = L"Hook and Monitoring";
			this->hookAndMonitoring->UseVisualStyleBackColor = true;
			this->hookAndMonitoring->Click += gcnew System::EventHandler(this, &Form1::hookAndMonitoring_Click);
			// 
			// unhook
			// 
			this->unhook->Location = System::Drawing::Point(427, 77);
			this->unhook->Name = L"unhook";
			this->unhook->Size = System::Drawing::Size(214, 82);
			this->unhook->TabIndex = 1;
			this->unhook->Text = L"Unhook";
			this->unhook->UseVisualStyleBackColor = true;
			this->unhook->Click += gcnew System::EventHandler(this, &Form1::unhook_Click);
			// 
			// logBox
			// 
			this->logBox->Location = System::Drawing::Point(55, 208);
			this->logBox->Multiline = true;
			this->logBox->Name = L"logBox";
			this->logBox->ReadOnly = true;
			this->logBox->ScrollBars = System::Windows::Forms::ScrollBars::Both;
			this->logBox->Size = System::Drawing::Size(586, 353);
			this->logBox->TabIndex = 2;
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(13, 24);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(700, 606);
			this->Controls->Add(this->logBox);
			this->Controls->Add(this->unhook);
			this->Controls->Add(this->hookAndMonitoring);
			this->Name = L"FAST-Monitor";
			this->Text = L"FAST-Monitor";
			this->ResumeLayout(false);
			this->PerformLayout();



		}
#pragma endregion

	private: System::Void hookAndMonitoring_Click(System::Object^ sender, System::EventArgs^ e) {

		mon(0);

	}

	private: System::Void unhook_Click(System::Object^ sender, System::EventArgs^ e) {
		mon(1);

	}

	public: System::Void logging(String^ text) {

		this->logBox->AppendText(text+"\n");
	}


	};

}


