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

uint16_t sum_byte(uint8_t x,uint8_t y){
    uint16_t data=0;

    data=x;
    data=(data<<8)+y;

    return data;
}

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
    int16_t seq,data,no=1;
    uint8_t flags=0;
    uint8_t *packet_checked=(uint8_t*)malloc(packet_len);
    memcpy(packet_checked,s7packet,packet_len);

    //exception handling
    if(packet_checked[0]!=0xff){
        printf("Error // Return code : %x\n",packet_checked[0]);
    }

    s7key=id;
    s7key=(s7key<<16)+index; 

    switch(s7key){
        case 0x00000000:
            for(seq = 12; seq<packet_len; seq+=2){
                data = packet_checked[12+(no-1)*2];
                data = (data<<8)+packet_checked[12+(no-1)*2+1];
                printf("SZL data tree (list count no. %d) SZL ID that exists : %x\n", no, data);
                no++;
            }
            break;
        case 0x00110000:
            for(seq = 12; seq<packet_len; seq+=28){
                printf("SZL data tree (list count no. %d)\n", no);
                data = packet_checked[seq];
                data = (data<<8)+packet_checked[seq+1];
                printf("Index : %x\n", data);
                printf("MlfB (Order number of the module) : ");
                for(int i = 0; i<20; i++) printf("%c", packet_checked[seq+2+i]);
                printf("\n");
                data = packet_checked[seq+22];
                data = (data<<8)+packet_checked[seq+23];
                printf("BGTyp (Module type ID) : %x\n", data);
                data = packet_checked[seq+24];
                data = (data<<8)+packet_checked[seq+25];
                printf("Ausbg (Version of the module or release of the operating system) : %x\n", data);
                data = packet_checked[seq+26];
                data = (data<<8)+packet_checked[seq+27];
                printf("Ausbe (Release of the PG description) : %x\n\n", data);
                no++;
            }
            break;
        case 0x001a0000:
            for(seq = 12; seq<packet_len; seq+=12){
                printf("SZL data tree (list count no. %d) ", no);
                printf("SZL partial list data :  ");
                for(int i = 0; i<12; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\n");
                no++;
            }
            break;
        case 0x001b0000:
            for(seq = 12; seq<packet_len; seq+=20){
                printf("SZL data tree (list count no. %d) ", no);
                for(int i = 0; i<20; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\n");
                no++;
            }
            break;
        case 0x001c0000:
            for(seq = 12; seq<packet_len-34; seq+=34){
                printf("SZL data tree (list count no. %d) ", no);
                for(int i = 0; i<34; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\n");
                no++;
            }
            data = packet_checked[seq];
            data = (data<<8)+packet_checked[seq+1];
            printf("SZL data tree [Fragment, complete response doesn't fit one PDU] ");
            printf("SZL data : %x\n", data);
            break;
        case 0x003a0000:
            printf("No data tree.\n");
            break;
        case 0x00740000:
            for(seq = 12; seq<packet_len; seq+=4){
                printf("SZL data tree (list count no. %d)\n", no);
                data = packet_checked[seq];
                data = (data<<8)+packet_checked[seq+1];
                printf("cpu_led_id : %x\n", data);
                data = (packet_checked[seq]&0x0B);
                printf("Bits 0, 1, 2 : Rack number : %x\n", data);
                data = (packet_checked[seq]&0x08);
                printf("Bits 3 : CPU Type (0=Standby, 1=Master) : %x\n", data);
                printf("Byte 1 : LED ID : %x\n", packet_checked[seq+1]);
                printf("\n");
                printf("Status of the LED : %s\n", packet_checked[seq+2]==0?"Off":"On");
                printf("Flashing status of the LED : %s\n", packet_checked[seq+2]==0?"Not flashing":"Flashing");
                no++;
            }
            break;
        case 0x00a00000:
            for(seq = 12; seq<packet_len; seq+=20){
                printf("SZL data tree (list count no. %d)\n", no);
                printf("Event ID : ");
                for(int i = 0; i<2; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\nEvent class : %x\n", (packet_checked[seq]&0xF0)/16);
                printf("Event entering : %x\n", (packet_checked[seq]&0x01));
                printf("Entry in diagnostic buffer : %s\n", (packet_checked[seq]&0x02)==0?"False":"True");
                printf("Internal error : %s\n", (packet_checked[seq]&0x04)==0?"False":"True");
                printf("External errer : %s\n", (packet_checked[seq]&0x08)==0?"False":"True");
                printf("Event number : %x\n", packet_checked[seq+1]);
                printf("Prioriry class : %x\n", packet_checked[seq+2]);
                printf("OB number : %x\n", packet_checked[seq+3]);
                printf("DatID : ");
                for(int i = 4; i<6; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\nINF01 Additional information 1 : ");
                for(int i = 6; i<8; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\nINF01 Additional information 2 : ");
                for(int i = 8; i<12; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\nS7 Timestamp - Year : 20%x", packet_checked[seq+12]);
                printf("\nS7 Timestamp - Month : %x", packet_checked[seq+13]);
                printf("\nS7 Timestamp - Day : %x", packet_checked[seq+14]);
                printf("\nS7 Timestamp - Hour : %x", packet_checked[seq+15]);
                printf("\nS7 Timestamp - Minute : %x", packet_checked[seq+16]);
                printf("\nS7 Timestamp - Second : %x", packet_checked[seq+17]);
                printf("\nS7 Timestamp - Milliseconds : %x%x", packet_checked[seq+18], (packet_checked[seq+19]/16));
                printf("\nS7 Tinestamp - Weekday : %x\n\n", (packet_checked[seq+19]&0x0F));
                no++;
            }
            break;
        case 0x01110001:
            seq = 12;
            data = packet_checked[seq];
            data = (data<<8)+packet_checked[seq+1];
            printf("Index : %x\n", data);
            printf("MlfB (Order number of the module) : ");
            for(int i = 0; i<20; i++) printf("%c", packet_checked[seq+2+i]);
            printf("\n");
            data = packet_checked[seq+22];
            data = (data<<8)+packet_checked[seq+23];
            printf("BGTyp (Module type ID) : %x\n", data);
            data = packet_checked[seq+24];
            data = (data<<8)+packet_checked[seq+25];
            printf("Ausbg (Version of the module or release of the operating system) : %x\n", data);
            data = packet_checked[seq+26];
            data = (data<<8)+packet_checked[seq+27];
            printf("Ausbe (Release of the PG description file) : %x\n\n", data);
            break;
        case 0x01120100:
            for(seq = 12; seq<packet_len; seq+=2){
                printf("SZL data tree (list count no. %d) ", no);
                printf("SZL partial list data : ");
                for(int i = 0; i<2; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\n");
                no++;
            }
            break;
        case 0x01120200:
                printf("No data tree.\n");
            break;
        case 0x01310001:
            for(seq = 12; seq<packet_len; seq+=40){
                printf("SZL data tree (list count no. %d) ", no);
                data = packet_checked[seq];
                data = (data<<8)+packet_checked[seq+1];
                printf("Index : %x\n", data);
                data = packet_checked[seq+2];
                data = (data<<8)+packet_checked[seq+3];
                printf("pdu (Maximum PDU size in bytes) : %x\n", data);
                data = packet_checked[seq+4];
                data = (data<<8)+packet_checked[seq+5];
                printf("anz (Maximum number of communication connections) : %x\n", data);
                printf("mpi_bps (Maximum data rate of the MPI in hexadecimal format) : ");
                for(int i = 6; i<10; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\nmkbus_bps (Maximum data rate of the communicaton bus) : ");
                for(int i = 10; i<14; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\nres (Reserved) : ");
                for(int i = 14; i<40; i++){
                    if((packet_checked[seq+i]&0xF0)==0x00) printf("0");
                    printf("%x", packet_checked[seq+i]);
                }
                printf("\n");
                no++;
            }
            break;
        case 0x01310002:
            print_onebyte_flag(packet_checked[14],funk0);
            print_onebyte_flag(packet_checked[15],funk1);
            print_onebyte_flag(packet_checked[16],funk2);
            print_onebyte_flag(packet_checked[20],trgereig0);
            print_onebyte_flag(packet_checked[21],trgereig1);
            break;
        case 0x01310005:
            printf("SZL data tree (list count no. %d)\n",1);
            for(seq=12;seq<packet_len;seq++){
                if(packet_checked[seq]&0xF0)
                    printf("%x",packet_checked[seq]);
                else{
                    printf("0%x",packet_checked[seq]);
                }
            }
            printf("\n");
            break;
        case 0x01310006:
            //flag
            break;
        case 0x01310009:
            printf("SZL data tree (list count no. %d)\n",1);
            for(seq=12;seq<packet_len;seq++){
                if(packet_checked[seq]&0xF0)
                    printf("%x",packet_checked[seq]);
                else{
                    printf("0%x",packet_checked[seq]);
                }
            }
            printf("\n");
            break;
        case 0x01320001:
            printf("SZL data tree (list count no. %d)\n",1);
            printf("res pg : %x\n",sum_byte(packet_checked[14],packet_checked[15]));
            printf("res os : %x\n",sum_byte(packet_checked[16],packet_checked[17]));
            printf("u pg : %x\n",sum_byte(packet_checked[18],packet_checked[19]));
            printf("u od : %x\n",sum_byte(packet_checked[20],packet_checked[21]));
            printf("proj : %x\n",sum_byte(packet_checked[22],packet_checked[23]));
            printf("auf : %x\n",sum_byte(packet_checked[24],packet_checked[25]));
            printf("free : %x\n",sum_byte(packet_checked[26],packet_checked[27]));
            printf("used : %x\n",sum_byte(packet_checked[28],packet_checked[29]));
            printf("last : %x\n",sum_byte(packet_checked[30],packet_checked[31]));
            printf("res : ");
            for(seq=32;seq<packet_len;seq++){
                if(packet_checked[seq]&0xF0)
                    printf("%x",packet_checked[seq]);
                else{
                    printf("0%x",packet_checked[seq]);
                }
            }
            printf("\n");
            break;
        case 0x01320004:
            printf("SZL data tree (list count no. %d)\n",1);
            printf("key : %x\n",sum_byte(packet_checked[14],packet_checked[15]));
            printf("param : %x\n",sum_byte(packet_checked[16],packet_checked[17]));
            printf("real : %x\n",sum_byte(packet_checked[18],packet_checked[19]));
            printf("bart_sch : %x\n",sum_byte(packet_checked[20],packet_checked[21]));
            printf("crst_wrst : %x\n",sum_byte(packet_checked[22],packet_checked[23]));
            printf("res : ");
            for(seq=24;seq<packet_len;seq++){
                if(packet_checked[seq]&0xF0)
                    printf("%x",packet_checked[seq]);
                else{
                    printf("0%x",packet_checked[seq]);
                }
            }
            printf("\n");
            break;
        case 0x01320008:
        case 0x01320009:
        case 0x0132000b:
            printf("SZL data tree (list count no. %d)\tSZL ID that exits : ",1);
            for(seq=12;seq<packet_len;seq++){
                if(packet_checked[seq]&0xF0)
                    printf("%x",packet_checked[seq]);
                else{
                    printf("0%x",packet_checked[seq]);
                }
            }
            printf("\n");
            break;
        case 0x01740006:
            printf("SZL data tree (list count no. %d)\tSZL ID that exits : ",1);
            printf("Rack number : %d\n",packet_checked[12]&0b00000111);
            printf("CPU Type (0=Standby, 1=Master) : %d\n",(packet_checked[12]&0b00001000)>>3);
            printf("LED ID : %d\n",packet_checked[13]);
            printf("Status of the LED : %s\n",packet_checked[14]==0?"OFF":"ON");
            printf("Flashing status of the  LED : %s\n",packet_checked[15]==0?"Not flashing":"flashing");
            break;
        case 0x02220001:
        case 0x02220050:
            printf("SZL data tree (list count no. %d)\tSZL ID that exits : ",1);
            for(seq=12;seq<packet_len;seq++){
                if(packet_checked[seq]&0xF0)
                    printf("%x",packet_checked[seq]);
                else{
                    printf("0%x",packet_checked[seq]);
                }
            }
            printf("\n");
            break;
        case 0x04240000:
            printf("SZL data tree (list count no. %d)\n",1);
            data=(packet_checked[12]<<8)|packet_checked[13];
            printf("ereig : %x\n",data);
            printf("ae : %x\n",packet_checked[14]);
            printf("buz-id : %x\n",packet_checked[15]);
            printf("anlinfo1 : %x\n",packet_checked[20]);
            printf("anlinfo2 : %x\n",packet_checked[21]);
            printf("anlinfo3 : %x\n",packet_checked[22]);
            printf("anlinfo4 : %x\n",packet_checked[23]);
            printf("time : ");
            for(seq=24;seq<packet_len;seq++){
                if(packet_checked[seq]&0xF0)
                    printf("%x",packet_checked[seq]);
                else{
                    printf("0%x",packet_checked[seq]);
                }
            }
            printf("\n");
            break;
        case 0x0d910000:
            printf("SZL data tree (list count no. %d)\tSZL ID that exits : ",1);
            for(seq=12;seq<packet_len;seq++){
                if(packet_checked[seq]&0xF0)
                    printf("%x",packet_checked[seq]);
                else{
                    printf("0%x",packet_checked[seq]);
                }
            }
            printf("\n");
            break;
        case 0x0f110000:
        case 0x0f120000:
        case 0x0f1a0000:
        case 0x0f1b0000:
        case 0x0f1c0000:
        case 0x0f3a0000:
        case 0x0f740000:
            printf("No data tree.\n");
            break;
        default:
            printf("Undefined s7 ID/Index\n");
            break;
    }

    printf("\n");
    free(packet_checked);
}
