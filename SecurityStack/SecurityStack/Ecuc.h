#ifndef ECUC_H
#define ECUC_H

/*Ecuc.h*/


typedef enum EcucPartitionIds
{
	ECUC_PARTITION_ID0
}EcucPartitionIds;


/****************************************************************************/
//Csm EcucPartition Definitions
typedef struct EcucPartition
{
	//TBD
	int dummy;
}EcucPartition;
/****************************************************************************/


extern EcucPartition EcucPartition_0;


#endif