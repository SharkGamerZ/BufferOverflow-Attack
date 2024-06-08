#include <stdio.h>
#include <string.h>

void funzioneGadget() {
  __asm__ volatile ("pop %%rdi\n\t"
      "ret"
      :
      :
      : "rdi");
}

int vuln() {
    printf("Inserisci la password: \n");
    
 
    char buff[512];

    gets(buff);

    if(strcmp(buff, "password123"))
    {
        printf ("Password Sbagliata \n");
    }
    else
    {
        printf ("Password Giusta\n");
    }

    return 0;
}

int main()
{
    printf("Benvenuto in questo sistema di sicurezza super sicuro!\n");
    vuln(); 
  	printf("Questo non lo vedrai!\n");

    return 0;
}

