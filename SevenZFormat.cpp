
#include "SevenZFormat.h"

/**
 *    Functions needed for LZMA decompression
 */
void *SzAlloc(void *p, size_t size) { p = p; return malloc(size); }
void SzFree(void *p, void *address) { p = p; free(address); }
ISzAlloc alloc = { SzAlloc, SzFree };

// Class SevenZFormat
SevenZFormat::SevenZFormat(){
    signature = "7z\xBC\xAF\x27\x1C";
    ext = "7z";
    name = "SevenZ";

    /*
     * At the star we are unable to detect if SevenZ format is encrypted,
     * so we suppose, it is.
     */
    is_encrypted = true;
}

SevenZFormat::SevenZFormat(const SevenZFormat& orig){
}

SevenZFormat::~SevenZFormat(){   
}

uint64_t SevenZFormat::SevenZUINT64(ifstream *stream){
    int bytes = 1;
    uint8_t firstByte;

    stream->read(reinterpret_cast<char*>(&firstByte), 1);
    while (firstByte & 0x80){
	SHL(firstByte);
	bytes++;
    }

    uint8_t num[bytes];
    num[0] = firstByte >> (bytes - 1);    // MSB
    if (bytes > 1)
	stream->read(reinterpret_cast<char*>(&num[1]), bytes-1);

    uint64_t sum = num[0];
    while(--bytes){
	sum = sum << 8;
	sum += num[bytes];
    }
    return sum;
}

SevenZStartHdr SevenZFormat::readStartHdr(ifstream *stream){

    SevenZStartHdr header;
    stream->seekg(12,stream->cur);   // 6 signature, 2 version, 4 sigCRC
    stream->read(reinterpret_cast<char*>(&header.NxtHdrOffset),sizeof(uint64_t));
    stream->read(reinterpret_cast<char*>(&header.NxtHdrSize),sizeof(uint64_t));
    stream->seekg(4,stream->cur);   // NextHeaderCRC

    return header;
}

SevenZFolder SevenZFormat::readFolder(ifstream *stream){
    SevenZFolder folder;
    folder.numCoders = SevenZUINT64(stream);
    folder.coder = new SevenZCoder[folder.numCoders];
    for (uint8_t i = 0; i < folder.numCoders; i++){
	SevenZCoder *coder = &(folder.coder[i]); 
	stream->read(reinterpret_cast<char*>(&coder->flags), 1);
	coder->coderIDSize = (coder->flags & 0x0f);
	coder->coderID = new uint8_t[coder->coderIDSize];
	stream->read(reinterpret_cast<char*>(coder->coderID), coder->coderIDSize);
	// most important and common IDs:
	// 03 01 01 - 7z LZMA
	// 06 f1 07 01 - 7zAES (AES-256 + SHA-256)

	if (coder->flags & 0x10){
	    coder->numInStreams = SevenZUINT64(stream);
	    folder.numInStreamsTotal += coder->numInStreams;

	    coder->numOutStreams = SevenZUINT64(stream);
	    folder.numOutStreamsTotal += coder->numOutStreams;
	}else {
	    // TODO: check this in the 7z sources
	    folder.numInStreamsTotal++;
	    folder.numOutStreamsTotal++;
	}
	if (coder->flags & 0x20){
	    coder->propertySize = SevenZUINT64(stream);
	    coder->property = new uint8_t[coder->propertySize];
	    stream->read(reinterpret_cast<char*>(coder->property), coder->propertySize);
	    //    for (int x = coder->propertySize; x > 0; x--)
	    //	stream->read(reinterpret_cast<char*>(&(coder->property[x-1])),1);
	}
    }
    for (uint64_t i = 0; i < (folder.numOutStreamsTotal - 1); i++){
	folder.inIndex = SevenZUINT64(stream);
	folder.outIndex = SevenZUINT64(stream);
    }

    uint64_t numPackStreams = folder.numInStreamsTotal - (folder.numOutStreamsTotal - 1);
    if (numPackStreams > 1){
	numPackStreams--;
	folder.index = new uint64_t[numPackStreams];
	for (uint8_t i = 0; i < numPackStreams; i++)	
	    folder.index[i] = SevenZUINT64(stream);
    }
    return folder;
}

uint32_t* SevenZFormat::CRCHdr(ifstream *stream, uint64_t numPackStreams,bool skip){ 
    uint32_t* crc;
    if (!skip)
	crc = new uint32_t[numPackStreams];
    //  for (uint64_t i = 0; i < numPackStreams; i++){
    uint8_t aad;
    stream->read(reinterpret_cast<char*>(&aad), 1);
    if (aad == 0){
	cerr << "File reading error. AllAreDefined == 0." << endl; // TODO: figure out how AAD works
	exit(153);
    }
    for (uint8_t j = 0; j < numPackStreams; j++)
	if(skip)
	    stream->seekg(4, stream->cur);
	else
	    stream->read(reinterpret_cast<char*>(&(crc[j])), 4);  // CRCs[NumDefined]
    //}
    return (skip ? NULL : crc);
}

void SevenZFormat::PackInfoHdr(ifstream *stream){	
    SevenZPackInfoHdr *packInfo = new SevenZPackInfoHdr;
    packInfo->packPos = 32 + SevenZUINT64(stream); // offset starting at 0x20 after startHeader
    packInfo->numPackStreams = SevenZUINT64(stream);

    uint8_t subsubHdrID = 1; // we just have to get into the cycle
    while (subsubHdrID != 0){   
	stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);
	if (subsubHdrID == SIZE){   
	    packInfo->packSize = new uint64_t[packInfo->numPackStreams];
	    for (uint64_t i = 0; i < packInfo->numPackStreams; i++)
		packInfo->packSize[i] = SevenZUINT64(stream);
	}else if (subsubHdrID == CRC){
	    // packInfo->crc = new uint32_t[packInfo->numPackStreams];
	    for (uint64_t i = 0; i < packInfo->numPackStreams; i++)
		packInfo->crc = CRCHdr(stream, packInfo->numPackStreams, READ);
	}
    }
    data.packInfo = packInfo;
}

void SevenZFormat::CodersHdr(ifstream *stream){	
    uint8_t subsubHdrID;
    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// (FOLDER)

    data.numFolders = SevenZUINT64(stream);
    data.folders = new SevenZFolder[data.numFolders];
    uint8_t ext;
    stream->read(reinterpret_cast<char*>(&ext), 1);
    if (ext == 1){
	cerr << "Unsupporte value. External == 1." << endl;	// TODO: add support for work with datastream indexes
	exit(154);
    }else{
	for (uint64_t i = 0; i < data.numFolders; i++)
	    data.folders[i] = readFolder(stream);
    }

    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	//(CODERUNPACKSIZE)
    if (subsubHdrID == CODERUNPACKSIZE){
	for (uint64_t i = 0; i < data.numFolders; i++){
	    data.folders[i].unPackSize = new uint64_t[data.folders[i].numOutStreamsTotal];
	    for (uint64_t j = 0; j < data.folders[i].numOutStreamsTotal; j++)
	    {
		data.folders[i].unPackSize[j] = SevenZUINT64(stream);
	    }
	}
	stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// (CRC)
    }

    if (subsubHdrID == CRC){	    
	data.packInfo->crc = CRCHdr(stream, data.numFolders, READ);
    }

    stream->read(reinterpret_cast<char*>(&subsubHdrID), 1);	// (END)

}

void SevenZFormat::SubStreamInfoHdr(ifstream *stream){
    uint8_t subsubHdrID = 1;
    uint64_t unpackStreamsInFolders = 0;
    while (subsubHdrID != 0){
	stream->read(reinterpret_cast<char*>(&subsubHdrID), 1); 
	if (subsubHdrID == NUMUNPACKSTR){
	    cout << "numFolders: " << data.numFolders << endl;
	    for (uint64_t i = 0; i < data.numFolders; i++)
		unpackStreamsInFolders += SevenZUINT64(stream);
	}
	if (subsubHdrID == SIZE){
	    if(unpackStreamsInFolders == 0)
		unpackStreamsInFolders = 1;
	    data.subStreamSize = new uint64_t[data.numFolders];
	    for (uint64_t i = 0; i < data.numFolders; i++)
		data.subStreamSize[i] = SevenZUINT64(stream);
	}
	if (subsubHdrID == CRC){
	    uint32_t end[3] = {0xff,0xff,0xff};
	    uint64_t count = 0;
	    stream->seekg(1, stream->cur);
	    while ((end[0] != 0x00 && end[1] != 0x00 && end[2] !=0x05 ) && count < 5){
		stream->seekg(4,stream->cur);
		stream->read(reinterpret_cast<char*>(&end[0]),1);
		stream->read(reinterpret_cast<char*>(&end[1]),1);
		stream->read(reinterpret_cast<char*>(&end[2]),1);
		stream->seekg(-3,stream->cur);
		//		cout << hex << "end[0]: " << end[0];
		//		cout << " end[1]: " << end[1];
		//		cout << " end[2]: " << end[2] << endl;
		count++;
	    }
	    stream->seekg(-4*count-1, stream->cur);
	    data.packInfo->crc = CRCHdr(stream, count, READ);
	}
    }
}

void SevenZFormat::readHeader(ifstream *stream){
    uint8_t subHdrID = 1;   // we just wanna get into the cycle
    while (subHdrID != 0){   // End 
	stream->read(reinterpret_cast<char*>(&subHdrID), 1);
	if (subHdrID == PACKINFO)
	    PackInfoHdr(stream);
	else if (subHdrID == UNPACKINFO){ 
	    CodersHdr(stream);
	    if (data.packInfo->crc == NULL)
		SubStreamInfoHdr(stream);
	    subHdrID = 0;	// fixed end we have all info we need

	}
    }
}

void SevenZFormat::copyStreamToBuffer(ifstream *stream, uint64_t pos, uint64_t size, uint8_t **buffer){

    // save state of stream
    streampos save_pos = stream->tellg();


    stream->seekg(pos, stream->beg);
    *buffer = new uint8_t[size];
    stream->read(reinterpret_cast<char*>(*buffer), size);

    // restore the state of stream
    stream->seekg(save_pos);
}

int SevenZFormat::decompressHdr(ifstream *istream, uint64_t numCoders){
    int lzma = 0;
    SizeT destlen = 0;
    SizeT srclen = data.packInfo->packSize[0];
    uint8_t *compbuf;
    uint8_t *rawbuf;
    SRes decode;
    ELzmaStatus status;

    for (int i = 0; i < numCoders; i++){
	if (data.folders[0].coder[i].coderID[0] == 0x03)
	    if (data.folders[0].coder[i].coderID[1] == 0x01){
		destlen = data.folders[0].unPackSize[0];
		rawbuf = new uint8_t[destlen];
		copyStreamToBuffer(istream, data.packInfo->packPos,\
			data.packInfo->packSize[0], &compbuf);
		decode = LzmaDecode((uint8_t*)rawbuf, &destlen,\
			compbuf, &srclen,\
			data.folders[0].coder[0].property,\
			data.folders[0].coder[0].propertySize,\
			LZMA_FINISH_END, &status, &alloc);
		if ( destlen != data.folders[0].unPackSize[0] || srclen != data.packInfo->packSize[0]){
		    cerr << "Something went wrong with decompression!" << endl;
		    cerr << "destlen: " << destlen << " unPackSize: " << data.folders[0].unPackSize[0] << endl;
		    cerr << " srclen: " << srclen << " packSize: " << data.packInfo->packSize[0] << endl; 
		    exit(156);
		}
		cout << "decode: " << decode << endl;
		// TODO: Might need some optimalization
		ofstream rawhdr;
		rawhdr.open ("raw.hdr", ios::out | ios::trunc | ios::binary);
		for (uint64_t i = 0; i < destlen; i++)
		    rawhdr << rawbuf[i];
		rawhdr.close(); 
	    }
    }
    return destlen;
}

void SevenZFormat::data4Cracking(ifstream *istream){
    copyStreamToBuffer(istream, data.packInfo->packPos,\
	    data.packInfo->packSize[0], &data.encData);
}

void SevenZFormat::readInitInfo(ifstream *stream){

    uint8_t hdrID;
    SevenZStartHdr sighdr = readStartHdr(stream);
    stream->seekg(sighdr.NxtHdrOffset,stream->cur); // move to Main Header
    stream->read(reinterpret_cast<char*>(&hdrID), 1);
    if (hdrID == HDR){
	// raw Main Header 
	// only when only one file is compress and Header is not encrypted
	data.type = RawHeader;
	stream->seekg(1,stream->cur);
	readHeader(stream); 
    }else if (hdrID == ENCHDR){
	data.type = EncHeader;
	readHeader(stream);
	codersInEncHdr = data.numFolders;
	if (data.numFolders == 1 && data.folders[0].numCoders == 1){
	    int fsize = decompressHdr(stream, data.folders[0].numCoders); 
	    if (fsize != 0 ){

		ifstream rawhdr; 
		rawhdr.open("raw.hdr", ios_base::binary);
		readHeader(&rawhdr);
		rawhdr.close();
		remove("raw.hdr");	    // clear the file
	    }
	} 
	// else : go cracking
    }
    data4Cracking(stream);
} 

void SevenZFormat::init(ifstream& stream){ 

    char buffer[6];
    data.keyLength = 256;	// there is no other option 
    readInitInfo(&stream);

    if (verbose)
	printInfo();
    stream.close();
    is_supported = true;
}

void SevenZFormat::printInfo(){
    uint64_t i;
    cout << "======= SevenZ information =======" << endl;
    cout << "Number of folders: " << data.numFolders << endl;
    cout << "Key length: " << data.keyLength << endl;
    for (i=0; i < data.numFolders; i++ )
	data.folders[i].printInfo();
    data.packInfo->printInfo();
    if (data.type == NONE)
	cout << "Encryption method is currently not supported by Wrathion." << endl;
    else{
	if (data.type == RawHeader)
	    cout << "Header is not encrypted nor compressed" << endl;
	else if (data.type == EncHeader){
	    if (codersInEncHdr == 1)
		cout << "Header is either compressed or encrypted" << endl;
	    else 
		cout << "Header is compressed and encrypted" << endl;
	}
	cout << "Encryption method: 7ZAES256 + SHA256" << endl;
    } 
    cout << "===============================" << endl;
}

SevenZInitData::SevenZInitData(){}

string uint8ToHex(uint8_t a) {
    
    stringstream ss;
    ss << HEX(a);
    return ss.str();
}
string uint8ToStr(uint8_t a) {
    
    stringstream ss;
    ss << static_cast<int>(a);
    return ss.str();
}

string printArray(uint8_t *array, uint8_t size) {
    string s;
    for (int i = 0; i < size; i++)
	s += ", " + uint8ToHex(array[i]) ;	
    return s;
}

string SevenZCoder::coderToString(uint8_t *array, uint8_t size) {
    return (printArray(array,size) + " size: " + uint8ToStr(size));
}

string SevenZCoder::propertyToString(uint8_t *array, uint8_t size) {
    return (printArray(array,size) + " size: " + uint8ToStr(size));
}

void SevenZCoder::printInfo() {
    cout << "Coder: " + coderToString(coderID, coderIDSize) << endl;
    cout << "Flags: " << HEX(flags) << dec<< endl;
    cout << "In streams: " << numInStreams << endl;
    cout << "Out streams: " << numOutStreams << endl;
    cout << "Property: " << propertyToString(property, propertySize) << endl; 
}

void SevenZFolder::printInfo() {
    for (short i = 0; i < numCoders; i++)
	coder[i].printInfo();
    cout << "Total InStreams: " << numInStreamsTotal << endl;
    cout << "Total OutStreams: " << numOutStreamsTotal << endl;

}

void SevenZPackInfoHdr::printInfo() {
    cout << "Packpos: " << packPos << endl;
    cout << "NumPackStreams: " << numPackStreams << endl;
    for (uint64_t i=0; i < numPackStreams; i++)
	cout << "PackSize: " << packSize[i] << endl;
}
