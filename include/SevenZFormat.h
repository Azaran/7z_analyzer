/* 
 * Copyright (C) 2016 Vojtech Vecera
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy 
 * of this software and associated documentation files (the "Software"), to deal 
 * in the Software without restriction, including without limitation the rights 
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
 * copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
 * SOFTWARE.
 * 
 */

#ifndef SevenZFORMAT_H
#define	SevenZFORMAT_H

#include <vector>
#include <bitset>
#include <iostream>
#include <string>
#include <cstdint>
#include <sstream>
#include <fstream>

#include "7zTypes.h"
#include "LzmaDec.h"


// HEADERS
#define END 0x00
#define HDR 0x01
#define ARCHPROP 0x02
#define ADDSTRINFO 0x03
#define MSTRINFO 0x04
#define FILESINFO 0x05
#define PACKINFO 0x06
#define UNPACKINFO 0x07
#define SUBSTRINFO 0x08
#define SIZE 0x09
#define CRC 0x0A
#define FOLDER 0x0B
#define CODERUNPACKSIZE 0x0C 
#define NUMUNPACKSTR 0x0D 
#define ENCHDR 0x17 

// CODERS ID
#define LZMACDR 0x030101
#define AESCDR 0x06f10701
// OTHERS
#define HEX(x) "0x" << hex << static_cast<int>(x)
#define SHL(x) (x = x << 1) // shift left by one bit 
#define READ 0
#define SKIP 1


using namespace std;

/**
 * For more information read 7zFormat.txt in 7-zip package
 */

/**
 * Type of file encryption
 */
enum SevenZEncType{
    RawHeader,
    EncHeader,
    NONE
};

struct SevenZCoder{
    uint8_t *coderID;
    uint8_t flags;
    uint8_t coderIDSize;
    uint64_t numInStreams;
    uint64_t numOutStreams;
    uint64_t propertySize;
    uint8_t *property;
    void printInfo();
    string coderToString(uint8_t *coder, uint8_t size);
    string propertyToString(uint8_t *coder, uint8_t size);
};

struct SevenZFolder{
    uint64_t numCoders;
    SevenZCoder *coder;
    uint64_t numInStreamsTotal = 0;
    uint64_t numOutStreamsTotal = 0;
    uint64_t inIndex;
    uint64_t outIndex;
    uint64_t *unPackSize;
    uint64_t *index;
    void printInfo();
};

struct SevenZStartHdr{
    uint64_t NxtHdrOffset;
    uint64_t NxtHdrSize;
};

struct SevenZPackInfoHdr{
    uint64_t packPos;
    uint64_t numPackStreams;
    uint64_t *packSize;
    uint32_t *crc = NULL;
    void printInfo();
};

struct SevenZInitData{
	SevenZInitData();
	SevenZEncType type;
	SevenZFolder *folders;
	SevenZPackInfoHdr *packInfo;
	uint64_t *subStreamSize = NULL;
	uint64_t numFolders;
	uint16_t keyLength;
	uint8_t *encData;

};

class FileFormat {
    protected:
	std::string signature;
	std::string ext;
	std::string name;
	bool is_encrypted;
	bool is_supported;
	bool verbose;
};

/**
 * Class for reading SevenZ file
 */
class SevenZFormat: public FileFormat {
public:
    SevenZFormat();
    SevenZFormat(const SevenZFormat& orig);
    ~SevenZFormat();
    void init(std::ifstream& stream);

protected:
    /**
     * Read one file in stream from PK\x03\x04 signature position
     * @param stream
     * @return 
     */
    SevenZInitData readOneFile(std::ifstream *stream);
    /**
     * Reads signature of 7z file and Start header structure from the file stream
     * @param stream
     * @return 
     */
    SevenZStartHdr readStartHdr(std::ifstream *stream);
    /**
     * Reads Folder structure (0x0B) from the file stream
     * @param stream
     * @return 
     */
    SevenZFolder readFolder(std::ifstream *stream);
    /**
     * Converts number from 7z proprietary encoding to standard UINT64
     * @param stream
     * @return 
     */
    uint64_t SevenZUINT64(std::ifstream *stream);
    /**
     * Reads structure of CRC (0x0A) from the file stream
     * @param stream, numPackStreams
     * @return 
     */
    uint32_t* CRCHdr(std::ifstream *stream, uint64_t numPackStreams, bool skip);
    /**
     * Reads PackInfo header structure for the file stream
     * @param stream, numPackStreams, skip
     */
    void PackInfoHdr(std::ifstream *stream);
    /**
     * Reads Coders header structure for the file stream
     * @param stream
     */
    void CodersHdr(std::ifstream *stream);
    /**
     * Root function for getting all information from the stream
     * @param stream
     */
    void readInitInfo(std::ifstream *stream);
    /**
     * Can read Main or Encryption header structure (0x01 | 0x17)
     * @param stream
     */
    void readHeader(std::ifstream *stream);
    /**
     * Print SevenZ encryption information obtained from the file
     */
    void printInfo();
    /**
     * LZMA decompressHdrion of data
     * @param stream, numCoders
     */
    int decompressHdr(ifstream *istream, uint64_t numCoders);
    /**
     * Reads SubStreamInfoHdr and searches for CRC entries
     * @param stream
     * @return 
     */
    void SubStreamInfoHdr(ifstream *stream);
    /**
     * Reads stream saved in the archive which will be used for cracking.      * @param stream
     */
    void data4Cracking(ifstream *istream);
    /**
     * It copies data from the position in the file into the memory buffer 
     * @param stream, pos, size, buffer
     */
    void copyStreamToBuffer(ifstream *stream, uint64_t pos, uint64_t size, uint8_t **buffer);
    
private:
    SevenZInitData data;
    uint64_t codersInEncHdr;

};

#endif	/* SevenZFORMAT_H */

#ifndef LZMA_ALLOC_FNC
#define LZMA_ALLOC_FNC
void *SzAlloc(void *p, size_t size);

void SzFree(void *p, void *address);
#endif

