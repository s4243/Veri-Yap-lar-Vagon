#include<stdio.h>
#include<stdlib.h>
struct Node
{
	int data;
	struct Node* next;
}*top = NULL;
struct Student {
	const char* name;
	const char* firstname;

};
int n = 0;
int m = 10;
int lokomatif;
void push(int);
void pop();
void display();

void main()
{
	int choice;
	int i = 0, m = 200;

	// Create the student's structure variable 
	// with n Student's records 
	struct Student student[200];

	// Get the students data 

	student[0].name = "sumeyya"; student[0].firstname = "akbulut";
	student[1].name = "kubra"; student[1].firstname = "akbel";
	student[2].name = "cihat";  student[2].firstname = "arslan";
	student[3].name = "ilknur"; student[3].firstname = "arslan";
	student[4].name = "metin"; student[4].firstname = "k�l�c";
	student[5].name = "baha";  student[5].firstname = "ergen";
	student[6].name = "rukiye";student[6].firstname = "esmer";
	student[7].name = "alin"; student[7].firstname = "g�ne�";
	student[8].name = "ya�mur";  student[8].firstname = "su";
	student[9].name = "ada";student[9].firstname = "g�ney";
	student[10].name = "ela"; student[10].firstname = "k�z�lkaya";
	student[11].name = "ay�e"; student[11].firstname = "�ahin";
	student[12].name = "tuncay";  student[12].firstname = "kara";
	student[13].name = "�ifa"; student[13].firstname = "kele�";
	student[14].name = "sebiha"; student[14].firstname = "dilek";
	student[15].name = "rabia";  student[15].firstname = "g�m��";
	student[16].name = "ayhan";student[16].firstname = "ak�n";
	student[17].name = "elmas"; student[17].firstname = "bulut";
	student[18].name = "b��ra";  student[18].firstname = "arslan";
	student[19].name = "�ebnur";student[19].firstname = "topal";
	student[20].name = "ali "; student[20].firstname = "vefa";
	student[21].name = "taha"; student[21].firstname = "kuru";
	student[22].name = "selin";  student[22].firstname = "demir";
	student[23].name = "nil�fer"; student[23].firstname = "g�l";
	student[24].name = "g�l"; student[24].firstname = "bahar";
	student[25].name = "s�meyra";  student[25].firstname = "do�an";
	student[26].name = "sebahat";student[26].firstname = "do�an";
	student[27].name = "kk"; student[27].firstname = "ll";
	student[28].name = "hatice";  student[28].firstname = "karabulut";
	student[29].name = "berat";student[29].firstname = "karabulut";
	student[30].name = "eda"; student[30].firstname = "ege";
	student[31].name = "efe"; student[31].firstname = "dadak";
	student[32].name = "elanur";  student[32].firstname = "b�y�k";
	student[33].name = "banu"; student[33].firstname = "dilce";
	student[34].name = "nur"; student[34].firstname = "dilce";
	student[35].name = "ahmet";  student[35].firstname = "kara";
	student[36].name = "ekrem";student[36].firstname = "gen�o�lu";
	student[37].name = "erdo�an"; student[37].firstname = "ergin";
	student[38].name = "bilgin";  student[38].firstname = "deniz";
	student[39].name = "deniz";student[39].firstname = "efeo�lu";
	student[40].name = "ula�"; student[40].firstname = "turan";
	student[41].name = "burak"; student[41].firstname = "levent";
	student[42].name = "�i�ek";  student[42].firstname = "y�cel";
	student[43].name = "hakime"; student[43].firstname = "�al";
	student[44].name = "bet�l"; student[44].firstname = "y�ce";
	student[45].name = "nazl�";  student[45].firstname = "beyaz";
	student[46].name = "nurhan";student[46].firstname = "�z�m";
	student[47].name = "levent"; student[47].firstname = "ay";
	student[48].name = "aleyna";  student[48].firstname = "ay";
	student[49].name = "rnakk";student[49].firstname = "ll";
	student[50].name = "sude"; student[50].firstname = "naz";
	student[51].name = "serpil"; student[51].firstname = "g�ne�";
	student[52].name = "k�bra";  student[52].firstname = "�zata";
	student[53].name = "mahmut"; student[53].firstname = "turan";
	student[54].name = "perihan"; student[54].firstname = "kara";
	student[55].name = "rumeysa";  student[55].firstname = "sar�";
	student[56].name = "cahit";student[56].firstname = "�irin";
	student[57].name = "akif"; student[57].firstname = "�enses";
	student[58].name = "b��ra";  student[58].firstname = "�enses";
	student[59].name = "sara";student[59].firstname = "can";
	student[60].name = "esra"; student[60].firstname = "�nl�";
	student[61].name = "burak"; student[61].firstname = "�zkan";
	student[62].name = "sevda";  student[62].firstname = "�zkan";
	student[63].name = "ahmet"; student[63].firstname = "durna";
	student[64].name = "merve"; student[64].firstname = "sat�lmis";
	student[65].name = "seda";  student[65].firstname = "y�ksel";
	student[66].name = "emine";student[66].firstname = "y�ksel";
	student[67].name = "feyza"; student[67].firstname = "�ahin";
	student[68].name = "emre";  student[68].firstname = "�ahin";
	student[69].name = "�rmak";student[69].firstname = "ila�";
	student[70].name = "sefa"; student[70].firstname = "ocak";
	student[71].name = "enes"; student[71].firstname = "ilim";
	student[72].name = "ismail";  student[72].firstname = "levent";
	student[73].name = "dilara"; student[73].firstname = "kutsal";
	student[74].name = "sevgi"; student[74].firstname = "kutsal";
	student[75].name = "bayram";  student[75].firstname = "direk";
	student[76].name = "elif";student[76].firstname = "direk";
	student[77].name = "fatma"; student[77].firstname = "k�l��";
	student[78].name = "mustafa";  student[78].firstname = "k�l��";
	student[79].name = "derya";student[79].firstname = "midilli";
	student[80].name = "veysel"; student[80].firstname = "mavi";
	student[81].name = "eda"; student[81].firstname = "ay";
	student[82].name = "aylin";  student[82].firstname = "ay";
	student[83].name = "edanur"; student[83].firstname = "kara";
	student[84].name = "kaan"; student[84].firstname = "karaday";
	student[85].name = "fikriye";  student[85].firstname = "arslan";
	student[86].name = "barboros";student[86].firstname = "ekinci";
	student[87].name = "s�la"; student[87].firstname = "erdo�mu�";
	student[88].name = "aleyna";  student[88].firstname = "cebe";
	student[89].name = "ay�e";student[89].firstname = "fidan";
	student[90].name = "ece"; student[90].firstname = "korkmaz";
	student[91].name = "�a�r�"; student[91].firstname = "g�le�";
	student[92].name = "lila";  student[92].firstname = "su";
	student[93].name = "mavi"; student[93].firstname = "y�ld�r�m";
	student[94].name = "murat"; student[94].firstname = "y�ld�r�m";
	student[95].name = "mert";  student[95].firstname = "kele�";
	student[96].name = "osman";student[96].firstname = "alt�no�lu";
	student[97].name = "medine"; student[97].firstname = "z�mr�t";
	student[98].name = "elmas";  student[98].firstname = "ta�";
	student[99].name = "arif";student[99].firstname = "b�y�k";
	student[100].name = "hamza"; student[100].firstname = "k���k";
	student[101].name = "serenay"; student[101].firstname = "k�z�lyayla";
	student[102].name = "lale";  student[102].firstname = "nur";
	student[103].name = "fidan"; student[103].firstname = "ak";
	student[104].name = "beytullah"; student[104].firstname = "�ahan";
	student[105].name = "ahmet";  student[105].firstname = "turan";
	student[106].name = "berk";student[106].firstname = "erg�l";
	student[107].name = "r�zgar"; student[107].firstname = "can";
	student[108].name = "can";  student[108].firstname = "berk";
	student[109].name = "kaz�m";student[109].firstname = "uzun";
	student[110].name = "ali"; student[110].firstname = "ayd�n";
	student[111].name = "arda"; student[111].firstname = "elo�lu";
	student[112].name = "meryem";  student[112].firstname = "huzur";
	student[113].name = "bahattin"; student[113].firstname = "k�l��";
	student[114].name = "zeynep"; student[114].firstname = "bulut";
	student[115].name = "b�lent";  student[115].firstname = "�ak�r";
	student[116].name = "neslihan";student[116].firstname = "g�zel";
	student[117].name = "esra"; student[117].firstname = "bak�r";
	student[118].name = "gamze";  student[118].firstname = "�elik";
	student[119].name = "leyla";student[119].firstname = "alt�n";
	student[120].name = "��heda"; student[120].firstname = "nur";
	student[121].name = "poyraz"; student[121].firstname = "duman";
	student[122].name = "yusuf"; student[122].firstname = "ali";
	student[123].name = "furkan";  student[123].firstname = "ahmet";
	student[124].name = "fahriye"; student[124].firstname = "bulut";
	student[125].name = "hale"; student[125].firstname = "tutan";
	student[126].name = "ay�e";  student[126].firstname = "�en";
	student[127].name = "fatma";student[127].firstname = "�zkan";
	student[128].name = "b��ra"; student[128].firstname = "�am";
	student[129].name = "hamza";  student[129].firstname = "�am";
	student[130].name = "zeynep";student[130].firstname = "erva";
	student[131].name = "r�veyda"; student[131].firstname = "ciner";
	student[132].name = "fadime"; student[132].firstname = "salim";
	student[133].name = "berk";  student[133].firstname = "salim";
	student[134].name = "seda"; student[134].firstname = "�nl�";
	student[135].name = "fatma"; student[135].firstname = "tanr�verdi";
	student[136].name = "��kran";  student[136].firstname = "mavi";
	student[137].name = "mehmet";student[137].firstname = "y�ce";
	student[138].name = "nuri"; student[138].firstname = "y�ce";
	student[139].name = "muhammed";  student[139].firstname = "y�ce";
	student[140].name = "m�nevver";student[140].firstname = "ayd�n";
	student[141].name = "s�meyya"; student[141].firstname = "gezen";
	student[142].name = "adem"; student[142].firstname = "ara�o�lu";
	student[143].name = "elif";  student[143].firstname = "ara�o�lu";
	student[144].name = "selim"; student[144].firstname = "ayday";
	student[145].name = "fadime"; student[145].firstname = "d�ger";
	student[146].name = "saime";  student[146].firstname = "olcay";
	student[147].name = "gizem";student[147].firstname = "ko�";
	student[148].name = "enes"; student[148].firstname = "ko�";
	student[149].name = "hazan";  student[149].firstname = "ak�nc�";
	student[150].name = "nil�fer";student[150].firstname = "ak�nc�";
	student[151].name = "tu�ba"; student[151].firstname = "�olak";
	student[152].name = "eray"; student[152].firstname = "ay";
	student[153].name = "fehime";  student[153].firstname = "ay";
	student[154].name = "hande"; student[154].firstname = "erdem";
	student[155].name = "s�la"; student[155].firstname = "erdem";
	student[156].name = "ca�la";  student[156].firstname = "g�l";
	student[157].name = "ismail";student[157].firstname = "uzun";
	student[158].name = "�inar"; student[158].firstname = "erdim";
	student[159].name = "�mit";  student[159].firstname = "�o�ar";
	student[160].name = "sabri";student[160].firstname = "bo�an";
	student[161].name = "efe"; student[161].firstname = "tura";
	student[162].name = "irem"; student[162].firstname = "ye�in";
	student[163].name = "s�la";  student[163].firstname = "erdo�mu�";
	student[164].name = "halime"; student[164].firstname = "ay";
	student[165].name = "zeki"; student[165].firstname = "g�ng�r";
	student[166].name = "uraz";  student[166].firstname = "kayg�laro�lu";
	student[167].name = "ismail";student[167].firstname = "levent";
	student[168].name = "naz"; student[168].firstname = "sevinc";
	student[169].name = "melike";  student[169].firstname = "sevinc";
	student[170].name = "fikri"; student[170].firstname = "bo�an";
	student[171].name = "sude"; student[171].firstname = "naz";
	student[172].name = "emine";  student[172].firstname = "akkaya";
	student[173].name = "�mm�han"; student[173].firstname = "kuzp�nar";
	student[174].name = "yasemin"; student[174].firstname = "dereli";
	student[175].name = "m�berra";  student[175].firstname = "keskin";
	student[176].name = "hasan";student[176].firstname = "alaca";
	student[177].name = "ercan"; student[177].firstname = "�elik";
	student[178].name = "ismail";  student[178].firstname = "sayan";
	student[179].name = "ceyhun";student[179].firstname = "�etinkaya";
	student[180].name = "zeynep"; student[180].firstname = "y�ld�r�m";
	student[181].name = "m�cahit"; student[181].firstname = "�zten";
	student[182].name = "cumhur";  student[182].firstname = "�zt�rk";
	student[183].name = "yunus"; student[183].firstname = "yaman";
	student[184].name = "mesut"; student[184].firstname = "�z";
	student[185].name = "dilay";  student[185].firstname = "��kmaz";
	student[186].name = "ibrahim";student[186].firstname = "aysundu";
	student[187].name = "durmu�"; student[187].firstname = "ceylan";
	student[188].name = "burak";  student[188].firstname = "g�ll�";
	student[189].name = "osman";student[189].firstname = "girbat";
	student[190].name = "serhat"; student[190].firstname = "pul";
	student[191].name = "elif"; student[191].firstname = "�ahin";
	student[192].name = "cafer";  student[192].firstname = "kurt";
	student[193].name = "fatih"; student[193].firstname = "ayg�n";
	student[194].name = "ferhat"; student[194].firstname = "ekinci";
	student[195].name = "nilden";  student[195].firstname = "d�nmez";
	student[196].name = "murat";student[196].firstname = "engin";
	student[197].name = "nurhan"; student[197].firstname = "aksoy";
	student[198].name = "h�seyin";  student[198].firstname = "k�k";
	student[199].name = "fatma";  student[199].firstname = "bulut";
	int seatnumber;
	printf("\n:: Stack using Linked List ::\n");
	while (1) {
		printf("\n****** MENU ******\n");
		printf("1. Push\n2. Pop\n3. Display\n4. Exit\n5. Passenger\n6. Carriage\n");
		scanf_s("%d", &choice);
		switch (choice) {
		case 1:
			printf("Koltuk Numarasi: ");
			scanf_s("%d", &seatnumber);
			push(seatnumber);
			printf("\tisim = %s\n", student[n].name);
			printf("\tsoyisim = %s\n", student[n].firstname);
			++n;
			break;

		case 2: pop();
			--n;
			printf("\tisim = %s\n", student[n].name);
			printf("\tsoyisim = %s\n", student[n].firstname);
			break;

		case 3: display();
			--n;
			for (n; n <= 0; n--)
			{
				printf("\tisim = %s\n", student[n].name);
				printf("\tsoyisim = %s\n", student[n].firstname);
			}
			break;
		case 4: exit(0);
		case 5:
			if (n <= 200)
			{
				printf("yolcu sayisi=%d", n);
			}
			else
			{
				printf("tren dolmustur baska bir seferde gorusmek uzere,iyi gunler");
			}
			break;

		case 6:
			lokomatif = n / 10;
			printf("lokomatif sayisi=%d", lokomatif + 1);
			break;
		default: printf("\nWrong selection!!! Please try again!!!\n");
		}
	}
}
void push(int value)
{
	struct Node* newNode;
	newNode = (struct Node*)malloc(sizeof(struct Node));
	newNode->data = value;
	if (top == NULL)
		newNode->next = NULL;
	else
		newNode->next = top;
	top = newNode;
	printf("\nYolcu eklenmistir,�yi yolculuklar dileriz.\n");

}
void pop()
{
	if (top == NULL)
		printf("\nYolcu yok,tren vagonlari bostur.\n");
	else {
		struct Node* temp = top;
		printf("\nTren vagonundan inen yolcu: %d", temp->data);
		top = temp->next;
		free(temp);
	}
}
void display()
{
	if (top == NULL)
		printf("\nYolcu yok,tren vagonlari bostur\n");
	else {
		struct Node* temp = top;
		while (temp->next != NULL) {
			printf("%d--->", temp->data);
			temp = temp->next;
		}
		printf("%d--->NULL", temp->data);

	}
}