#include<stdio.h>
#include<stdlib.h>
#include "uthash.h"

typedef struct onebyte_data{
    char s[50];
    uint8_t flag;
}odata;

static odata funk0[8];
static odata funk1[8];
static odata funk2[8];
static odata trgereig0[8];
static odata trgereig1[8];


void init_flag(){
  strcpy(funk0[0].s,"Reserverd");
  strcpy(funk0[1].s,"BLock status");
  strcpy(funk0[2].s,"Variable status");
  strcpy(funk0[3].s,"Output ISTACK");
  strcpy(funk0[4].s,"Output BSTACK");
  strcpy(funk0[5].s,"Output LSTACK");
  strcpy(funk0[6].s,"Time measurement from");
  strcpy(funk0[7].s,"Force selection");

  strcpy(funk1[0].s,"Modify variable");
  strcpy(funk1[1].s,"Force");
  strcpy(funk1[2].s,"Breakpoint");
  strcpy(funk1[3].s,"Exit HOLD");
  strcpy(funk1[4].s,"Memory reset");
  strcpy(funk1[5].s,"Disable job");
  strcpy(funk1[6].s,"Enable job");
  strcpy(funk1[7].s,"Delete job");

  strcpy(funk2[0].s,"Read job list");
  strcpy(funk2[1].s,"Read job");
  strcpy(funk2[2].s,"Replace job");
  strcpy(funk2[3].s,"Reserved");
  strcpy(funk2[4].s,"Reserved");
  strcpy(funk2[5].s,"Reserved");
  strcpy(funk2[6].s,"Reserved");
  strcpy(funk2[7].s,"Reserved");

  strcpy(trgereig0[0].s,"Immediately");
  strcpy(trgereig0[1].s,"System trigerr");
  strcpy(trgereig0[2].s,"System checkpoint main cycle start");
  strcpy(trgereig0[3].s,"System checkpoint main cycle end");
  strcpy(trgereig0[4].s,"Mode transition RUN-STOP");
  strcpy(trgereig0[5].s,"After code address");
  strcpy(trgereig0[6].s,"Code address area");
  strcpy(trgereig0[7].s,"Data address");

  strcpy(trgereig1[0].s,"Data address area");
  strcpy(trgereig1[1].s,"Local data address");
  strcpy(trgereig1[2].s,"Local data address area");
  strcpy(trgereig1[3].s,"Range trigger");
  strcpy(trgereig1[4].s,"Before code address");
  strcpy(trgereig1[5].s,"Reserved");
  strcpy(trgereig1[6].s,"Reserved");
  strcpy(trgereig1[7].s,"Reserved");

  for(int i=0;i<8;i++){
    funk0[i].flag=0;
    funk1[i].flag=0;
    funk2[i].flag=0;
    trgereig0[i].flag=0;
    trgereig1[i].flag=0;
  }
}

void print_onebyte_flag(uint8_t flags, odata* func){

    for(int i=0;i<8;i++){
        if(((flags>>i)&0x01)==0x01)
            func[i].flag=1;
        else
            func[i].flag=0;
    }

    for(int i=0;i<8;i++){
        printf("  %s : ",func[i].s);
        if(func[i].flag==1)
            printf("True\n");
        else
            printf("False\n");  
    }

    printf("\n");
}

void bit_analysis(uint8_t *s7packet,unsigned long packet_len,uint16_t id, uint16_t index){

    init_flag();
    uint32_t s7key=0;
    uint8_t flags=0;
    uint8_t *packet_checked=(uint8_t*)malloc(packet_len);
    memcpy(packet_checked,s7packet,packet_len);

    s7key=id;
    s7key=(s7key<<16)+index;

    switch(s7key){
        case 0x01310002:
            print_onebyte_flag(packet_checked[14],funk0);
            print_onebyte_flag(packet_checked[15],funk1);
            print_onebyte_flag(packet_checked[16],funk2);
            break; 

        default:
        //undefined s7key
            break;

        
    }

    printf("\n");
    free(packet_checked);
}