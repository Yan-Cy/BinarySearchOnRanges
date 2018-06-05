#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <stack>
#include <algorithm>
#include <map>
#include <cstdint>

using namespace std;

#define TEST_FILE "MillionIPAddrOutput.txt"
//#define TEST_FILE "sample_test.txt"
#define OUTPUT_FILE "nexthops.txt"

struct entry {
    uint32_t start;
    uint32_t end;
    string nextHop;
};

struct mark {
    uint32_t addr;
    string greaterHop;
    string equalHop;
    bool isStart;
    uint32_t length;
};

vector<entry> rangesTable;
vector<mark> searchTable;


// bool entrySort (entry a,entry b) {
//     if (a.start < b.start) {
//         return true;
//     } else if (a.start == b.start){
//         return a.end < b.end;
//     }
//     return false; 
// }

bool markSort (mark a, mark b) {
    return a.addr < b.addr;
    // if (a.addr < b.addr) {
    //     return true;
    // } else if (a.addr == b.addr && a.isStart) {
    //     return true;
    // } else {
    //     return false;
    // }
}

uint32_t strToInt(const string& str){
    // convert an IP string to int

    uint32_t res = 0;
    uint32_t shifter = 1 << 24;
    stringstream ss(str);
    string number;
    while(getline(ss, number, '.')){
        res += stoi(number) * shifter;
        shifter >>= 8;
    }
    return res;
}

pair<uint32_t, uint32_t> parsePrefix(const string& str){
    // return the start and end points of a prefix

    uint32_t ip, mask;
    uint32_t start, end;
    pair<uint32_t, uint32_t> p;
    int shifter;

    bool hasMask = false;
    for (int i=0; i < str.length(); i++){
        if (str[i] == '/'){
            hasMask = true;
            ip = strToInt(str.substr(0,i));
            shifter = 32 - stoi(str.substr(i+1));
            mask = UINT32_MAX >> shifter << shifter;
        }
    }
    if (!hasMask){
        ip = strToInt(str);
        mask = UINT32_MAX;
    }
    start = ip & mask;
    end = ip | (~mask);
    p = make_pair(start, end);
    return p;
}

void parseLine(const string& line){
    // add one entry to rangesTable

    if (line[3]==' '){
        return;
    }

    string prefixStr, nextHopStr;
    stringstream ss(line.substr(3));
    ss >> prefixStr >> nextHopStr;
    pair<uint32_t,uint32_t> p = parsePrefix(prefixStr);

    entry e;
    e.start = p.first;
    e.end = p.second;
    e.nextHop = nextHopStr;
    rangesTable.push_back(e);
}

void generateSearchTable() {
    // generate the search table for binary search comparison.

    mark m;
    stack<string> S;
    vector<mark> tempMarks;     //temporally save all the 2N+1 marks
    map<uint32_t, int> mapIdx;  //save the key-value pair of address-indexInSearchTable

    m.addr = 0;
    m.greaterHop = m.equalHop = "-";
    m.isStart = true;
    m.length = UINT32_MAX;
    tempMarks.push_back(m);    

    for (int i = 0; i < rangesTable.size(); i++) {
        m.addr = rangesTable[i].start;
        m.greaterHop = rangesTable[i].nextHop;
        m.equalHop = rangesTable[i].nextHop;
        m.isStart = true;
        m.length = rangesTable[i].end - rangesTable[i].start;
        tempMarks.push_back(m);

        m.addr = rangesTable[i].end;
        m.greaterHop = "-";
        m.equalHop = rangesTable[i].nextHop;
        m.isStart = false;
        m.length = rangesTable[i].end - rangesTable[i].start;
        tempMarks.push_back(m);
    }

    // calculate greater for end points.
    sort(tempMarks.begin(), tempMarks.end(), markSort);
    S.push("-");
    for (int i = 0; i < tempMarks.size(); ) {
        // if (tempMarks[i].isStart) {
        //     S.push(tempMarks[i].equalHop);
        //     continue;
        // }
        // S.pop();
        // tempMarks[i].greaterHop = S.top();

        // find a set of marks which have the same addr.
        vector<mark> sameMarks;
        sameMarks.push_back(tempMarks[i]);
        int size = 1;
        while (i + size < tempMarks.size() && tempMarks[i + size - 1].addr == tempMarks[i + size].addr) {
            sameMarks.push_back(tempMarks[i + size]);
            size++;
        }
        // decide the index where the next set of same addr should start.
        i = i + size;

        uint32_t finalAddr = sameMarks[0].addr;
        string finalEqual = "-";
        string finalGreater = "-";
        
        // deal with equal
        uint32_t minLength = UINT32_MAX;
        for (int idx = 0; idx < sameMarks.size(); idx++) {
            if (sameMarks[idx].length < minLength) {
                finalEqual = sameMarks[idx].equalHop;
                minLength = sameMarks[idx].length;
            }
            // BTW push in the stack all the left bracket of the exact points first, 
            // in order to make sure all left brackets are pushed earlier than right brackets
            if (sameMarks[idx].isStart && sameMarks[idx].length == 0) {
                S.push(sameMarks[idx].equalHop);
            }
        }

        // deal with greater, first scan on right brackets.
        for (int idx = 0; idx < sameMarks.size(); idx++) {
            if (!sameMarks[idx].isStart) {
                S.pop();
            }
        }

        // deal with greater, second scan on left brackets.
        bool hasStart = false;
        minLength = UINT32_MAX;
        for (int idx = 0; idx < sameMarks.size(); idx++) {
            if (!sameMarks[idx].isStart) {
                continue;
            }
            hasStart = true;
            if (sameMarks[idx].length < minLength) {
                finalGreater = sameMarks[idx].equalHop;
                minLength = sameMarks[idx].length;
            }
            // the exact points' left brackets have been pushed before.
            if (sameMarks[idx].length != 0) {
                S.push(sameMarks[idx].equalHop);
            }
        }
        if (!hasStart) {
            finalGreater = S.top();
        }

        mark m;
        m.addr = finalAddr;
        m.equalHop = finalEqual;
        m.greaterHop = finalGreater;
        searchTable.push_back(m);
    }

}

vector<uint32_t> getIPs(string filename) {
    ifstream ipfile(filename);
    string line;
    vector<uint32_t> ips;
    int cnt = 0;
    while (getline(ipfile, line)) {
        // cout << line << endl;
        cnt++;
        ips.push_back(strToInt(line));
    }
    cout << "Number of IPs to test: " << cnt << endl;
    ipfile.close();
    return ips;
}

string binary_search(uint32_t ip, vector<mark> &search_table) {
    // cout << ip << " ";
    // static int cnt = 0;
    int l = 0, r = search_table.size() - 1;
    while (l < r - 1) {
        int mid = (l + r) >> 1;
        // cout << l << " " << r << " " << mid << endl;
        // cout << search_table[mid].addr << " " << ip << endl << endl;
        if (search_table[mid].addr == ip) {
            return search_table[mid].equalHop;
        }
        else if (search_table[mid].addr > ip) {
            r = mid;
        }
        else l = mid;
    }

    if (search_table[l].addr == ip) {
        return search_table[l].equalHop;
    }
    if (search_table[r].addr == ip) {
        return search_table[r].equalHop;
    }
    if (search_table[r].addr < ip) {
        //cout << "out of bound!" << ip << endl;
        //cout << "range: " << search_table[0].addr << " to " << search_table[search_table.size() - 1].addr << endl;
        //cout << ++cnt << endl;
        return search_table[r].greaterHop;
    }
    if (search_table[l].addr < ip) {
        return search_table[l].greaterHop;
    }

    cout << "out of bound! " << ip << endl;
    cout << "range: " << search_table[0].addr << " to " << search_table[search_table.size() - 1].addr << endl;

    if (l > r) {
        cout << "!!!" << endl;
    }
    
    return "-"; 
}


int main(int argc, const char *argv[]) {
    clock_t begin_time = clock();

    cout << "Parsing input file..." << endl;
    ifstream inputFile ("bgptable.txt");
    string line;
    
    while(getline(inputFile, line)){
        parseLine(line);
    }
    cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << " s" << endl;
    /*
    int cnt = 200;
    while(getline(inputFile, line) && cnt > 0){
        parseLine(line);
        cnt--;
    }
    */
    cout << "Generating search table..." << endl;
    begin_time = clock();
    generateSearchTable();
    cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << " s" << endl;

    /*
    cout << "---------------------------------" << endl;
    cout <<  "Prefix Range Table" << endl;
    cout <<  "start  end  nextHop" << endl;
    for(int i = 0; i < rangesTable.size(); i++){
        cout << rangesTable[i].start << " ";
        cout << rangesTable[i].end << " ";
        cout << rangesTable[i].nextHop << endl;
    }
    
    cout << "---------------------------------" << endl;
    cout <<  "Search Table" << endl;
    cout <<  "markAddress  equalHop   greaterHop" << endl;
    for(int i = 0; i < searchTable.size(); i++){
        cout << searchTable[i].addr << " ";
        cout << searchTable[i].equalHop << " ";
        cout << searchTable[i].greaterHop << endl;
    }
    */

    cout << "---------------------------------" << endl;
    cout <<  "Table Size" << endl;
    cout << "rangeTable:" << rangesTable.size() << endl;
    cout << "searchTable:" << searchTable.size() << endl;
    cout << "---------------------------------" << endl;
    
    cout << "Reading test IPs from " << TEST_FILE << endl;
    begin_time = clock();
    vector<uint32_t> ips = getIPs(TEST_FILE);
    cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << " s" << endl;

    cout << "Doing binary search..." << endl;
    begin_time = clock();
    vector<string> nexthops;
    for (int i = 0; i < ips.size(); i++) {
        nexthops.push_back(binary_search(ips[i], searchTable));
    }
    cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << " s" << endl;

    //------------------write results to file--------------------------
    cout << "Saving results to " << OUTPUT_FILE << "..." << endl;
    begin_time = clock();
    ofstream outputFile (OUTPUT_FILE);
    if (outputFile.is_open()) {
        for (int i = 0; i < nexthops.size(); i++) {
            outputFile << nexthops[i] << endl; 
        }
        outputFile.close();
    }
    cout << float( clock () - begin_time ) /  CLOCKS_PER_SEC << " s" << endl;

    return 0;
}