#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <stack>
#include <algorithm>

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

    m.addr = 0;
    m.greaterHop = m.equalHop = "-";
    m.isStart = true;
    searchTable.push_back(m);

    int cnt = 0;

    for (int i = 0; i < rangesTable.size(); i++) {
        m.addr = rangesTable[i].start;
        m.greaterHop = rangesTable[i].nextHop;
        m.equalHop = rangesTable[i].nextHop;
        m.isStart = true;
        searchTable.push_back(m);

        m.addr = rangesTable[i].end;
        m.greaterHop = "-";
        m.equalHop = rangesTable[i].nextHop;
        m.isStart = false;
        searchTable.push_back(m);
        if (rangesTable[i].start == rangesTable[i].end) {
            cnt++;
        }
    }

    cout << cnt << endl;

    sort(searchTable.begin(), searchTable.end(), markSort);
    S.push("-");
    cnt = 0;
    for (int i = 1; i < searchTable.size(); i++) {
        // cout << cnt << " " << searchTable[i].addr << " " << searchTable[i].isStart << endl;
        if (searchTable[i].isStart) {
            cnt++;
            S.push(searchTable[i].equalHop);
            continue;
        }
        cnt--;
        // cout <<  S.size() << endl;
        S.pop();
        searchTable[i].greaterHop = S.top();
    }
}

vector<uint32_t> getIPs(string filename) {
    ifstream ipfile(filename);
    string line;
    vector<uint32_t> ips;
    while (getline(ipfile, line)) {
        // cout << line << endl;
        ips.push_back(strToInt(line));
    }
    ipfile.close();
    return ips;
}

string binary_search(uint32_t ip, vector<mark> &search_table) {
    // cout << ip << " ";
    int l = 0, r = search_table.size() - 1;
    while (l < r) {
        int mid = (l + r + 1) >> 1;
        if (search_table[mid].addr == ip) {
            return search_table[mid].equalHop;
        }
        else if (search_table[mid].addr > ip) {
            r = mid - 1;
        }
        else l = mid + 1;
    }

    if (l == r) {
        if (search_table[l].addr == ip) {
            return search_table[l].equalHop;
        }
        else if (search_table[l].addr < ip){
            return search_table[l].greaterHop;
        }
    }
    
    return "-"; 
}

int main(int argc, const char *argv[]) {
    cout << "Reading input file..." << endl;
    ifstream inputFile ("bgptable.txt");
    string line;
    
    while(getline(inputFile, line)){
        parseLine(line);
    }

    // int cnt = 200;
    // while(getline(inputFile, line) && cnt > 0){
    //    parseLine(line);
    //    cnt--;
    //}

    inputFile.close();

    /* Print Prefix Range Table
    cout << "---------------------------------" << endl;
    cout <<  "Prefix Range Table" << endl;
    cout <<  "start  end  nextHop" << endl;
    for(int i = 0; i < rangesTable.size(); i++){
        cout << rangesTable[i].start << " ";
        cout << rangesTable[i].end << " ";
        cout << rangesTable[i].nextHop << endl;
    }
    */

    cout << "Generating search table..." << endl;
    generateSearchTable();

    /* Print Search Table
    cout << "---------------------------------" << endl;
    cout <<  "Search Table" << endl;
    cout <<  "markAddress  greaterHop  equalHop  isStart" << endl;
    for(int i = 0; i < searchTable.size(); i++){
        cout << searchTable[i].addr << " ";
        cout << searchTable[i].greaterHop << " ";
        cout << searchTable[i].equalHop << " ";
        cout << searchTable[i].isStart << endl;
    }
    */

    cout << "---------------------------------" << endl;
    cout <<  "Table Size" << endl;
    cout << "rangeTable:" << rangesTable.size() << endl;
    cout << "searchTable:" << searchTable.size() << endl;

    cout << endl;

    cout << "Reading test IPs from " << TEST_FILE << "..." << endl;
    vector<uint32_t> ips = getIPs(TEST_FILE);
    cout << "Doing binary search..." << endl;
    vector<string> nexthops;
    for (int i = 0; i < ips.size(); i++) {
        nexthops.push_back(binary_search(ips[i], searchTable));
    }
    //------------------write results to file--------------------------
    cout << "Saving results to " << OUTPUT_FILE << "..." << endl;
    ofstream outputFile (OUTPUT_FILE);
    if (outputFile.is_open()) {
        for (int i = 0; i < nexthops.size(); i++) {
            outputFile << nexthops[i] << endl; 
        }
        outputFile.close();
    }
    return 0;
}

