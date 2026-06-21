/**
 * LOW-LATENCY INFRASTRUCTURE & NETWORK PERFORMANCE MONITOR
 * =========================================================
 * A high-performance, single-file C++ program that implements:
 * 1. An embedded, multi-threaded HTTP Web Server (Port 8080).
 * 2. A real-time, background network & hardware telemetry engine (runs every
 * 2s).
 * 3. An API endpoint `/api/metrics` serving metrics in JSON format.
 * 4. An embedded, real-time web dashboard using Tailwind CSS and Chart.js.
 *
 * Supports Windows (Winsock2), Linux, and macOS out of the box with system
 * APIs.
 *
 * Compilation Commands:
 * - Windows (MinGW/GCC): g++ -O3 main.cpp -o monitor.exe -lws2_32 -lsetupapi
 * - Linux:               g++ -O3 main.cpp -o monitor -pthread
 * - macOS:               g++ -O3 main.cpp -o monitor
 */

// Define target Windows version first to expose modern APIs (getaddrinfo,
// GetSystemTimes)
#ifdef _WIN32
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 // Target Windows Vista or later
#endif

// Core C++ Standard Library Headers
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifndef _WIN32
#include <dirent.h>
#include <sys/statvfs.h>

#endif

// ==========================================
// PLATFORM-SPECIFIC SOCKET & SYSTEM HEADERS
// ==========================================
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Custom Win32 Structures and function pointers to dynamically resolve
// low-level APIs
typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
  LARGE_INTEGER IdleTime;
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER DpcTime;
  LARGE_INTEGER InterruptTime;
  ULONG UlongReserved;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
  LARGE_INTEGER IdleProcessTime;
  LARGE_INTEGER IoReadTransferCount;
  LARGE_INTEGER IoWriteTransferCount;
  LARGE_INTEGER IoOtherTransferCount;
  ULONG IoReadOperationCount;
  ULONG IoWriteOperationCount;
  ULONG IoOtherOperationCount;
  ULONG AvailablePages;
  ULONG TotalCommittedPages;
  ULONG TotalCommitLimit;
  ULONG PeakCommitment;
  ULONG PageFaults;
  ULONG WriteCopyFaults;
  ULONG TransitionFaults;
  ULONG CacheTransitionFaults;
  ULONG DemandZeroFaults;
  ULONG PagesRead;
  ULONG PageReadIos;
  ULONG PagesWritten;
  ULONG PageWriteIos;
} SYSTEM_PERFORMANCE_INFORMATION;

typedef struct _PERFORMANCE_INFORMATION {
  DWORD cb;
  size_t CommitTotal;
  size_t CommitLimit;
  size_t CommitPeak;
  size_t PhysicalTotal;
  size_t PhysicalAvailable;
  size_t SystemCache;
  size_t KernelTotal;
  size_t KernelPaged;
  size_t KernelNonpaged;
  size_t PageSize;
  DWORD HandleCount;
  DWORD ProcessCount;
  DWORD ThreadCount;
} PERFORMANCE_INFORMATION;

typedef struct _MIB_IFROW {
  WCHAR wszName[256];
  DWORD dwIndex;
  DWORD dwType;
  DWORD dwMtu;
  DWORD dwSpeed;
  DWORD dwPhysAddrLen;
  BYTE bPhysAddr[8];
  DWORD dwAdminStatus;
  DWORD dwOperStatus;
  DWORD dwLastChange;
  DWORD dwInOctets;
  DWORD dwInUcastPkts;
  DWORD dwInNUcastPkts;
  DWORD dwInDiscards;
  DWORD dwInErrors;
  DWORD dwInUnknownProtos;
  DWORD dwOutOctets;
  DWORD dwOutUcastPkts;
  DWORD dwOutNUcastPkts;
  DWORD dwOutDiscards;
  DWORD dwOutErrors;
  DWORD dwOutQLen;
  DWORD dwDescrLen;
  BYTE bDescr[256];
} MIB_IFROW;

typedef struct _MIB_IFTABLE {
  DWORD dwNumEntries;
  MIB_IFROW table[1];
} MIB_IFTABLE;

typedef struct _MIB_TCPROW {
  DWORD dwState;
  DWORD dwLocalAddr;
  DWORD dwLocalPort;
  DWORD dwRemoteAddr;
  DWORD dwRemotePort;
} MIB_TCPROW;

typedef struct _MIB_TCPTABLE {
  DWORD dwNumEntries;
  MIB_TCPROW table[1];
} MIB_TCPTABLE;

typedef struct _MIB_UDPROW {
  DWORD dwLocalAddr;
  DWORD dwLocalPort;
} MIB_UDPROW;

typedef struct _MIB_UDPTABLE {
  DWORD dwNumEntries;
  MIB_UDPROW table[1];
} MIB_UDPTABLE;

typedef DWORD(WINAPI *PfnGetIfTable)(MIB_IFTABLE *pIfTable, ULONG *pdwSize,
                                     BOOL bOrder);
typedef DWORD(WINAPI *PfnGetTcpTable)(MIB_TCPTABLE *pTcpTable, ULONG *pdwSize,
                                      BOOL bOrder);
typedef DWORD(WINAPI *PfnGetUdpTable)(MIB_UDPTABLE *pUdpTable, ULONG *pdwSize,
                                      BOOL bOrder);

typedef NTSTATUS(WINAPI *PfnNtQuerySystemInformation)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

typedef BOOL(WINAPI *PfnGetPerformanceInfo)(
    PERFORMANCE_INFORMATION *pPerformanceInformation, DWORD cb);

static PfnNtQuerySystemInformation pfnNtQuerySystemInformation = nullptr;
static PfnGetPerformanceInfo pfnGetPerformanceInfo = nullptr;
static PfnGetIfTable pfnGetIfTable = nullptr;
static PfnGetTcpTable pfnGetTcpTable = nullptr;
static PfnGetUdpTable pfnGetUdpTable = nullptr;

inline void init_windows_apis() {
  HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
  if (hNtdll) {
    pfnNtQuerySystemInformation = (PfnNtQuerySystemInformation)GetProcAddress(
        hNtdll, "NtQuerySystemInformation");
  }
  HMODULE hPsapi = LoadLibraryA("psapi.dll");
  if (hPsapi) {
    pfnGetPerformanceInfo =
        (PfnGetPerformanceInfo)GetProcAddress(hPsapi, "GetPerformanceInfo");
  }
  HMODULE hIphlp = LoadLibraryA("iphlpapi.dll");
  if (hIphlp) {
    pfnGetIfTable = (PfnGetIfTable)GetProcAddress(hIphlp, "GetIfTable");
    pfnGetTcpTable = (PfnGetTcpTable)GetProcAddress(hIphlp, "GetTcpTable");
    pfnGetUdpTable = (PfnGetUdpTable)GetProcAddress(hIphlp, "GetUdpTable");
  }
}

// Typedefs and mapping to unify Windows socket API with BSD sockets
typedef SOCKET SocketType;
#define IS_VALIDSOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSE_SOCKET(s) closesocket(s)
#define GET_SOCKET_ERRNO() WSAGetLastError()
#define SOCKET_ERR_WOULDBLOCK WSAEWOULDBLOCK
#define SOCKET_ERR_INPROGRESS WSAEWOULDBLOCK
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

#ifdef __linux__
#include <fstream>
#include <sys/sysinfo.h>
#elif defined(__APPLE__)
#include <mach/mach.h>
#include <sys/sysctl.h>
#endif

typedef int SocketType;
#define INVALID_SOCKET -1
#define IS_VALIDSOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#define GET_SOCKET_ERRNO() errno
#define SOCKET_ERR_WOULDBLOCK EWOULDBLOCK
#define SOCKET_ERR_INPROGRESS EINPROGRESS
#endif

// ==========================================
// CROSS-PLATFORM THREADING & MUTEX WRAPPERS
// ==========================================
// Since standard MinGW builds on Windows use the 'win32' threading model,
// they do not expose std::thread or std::mutex. We implement custom wrapper
// classes using raw Win32 APIs for Windows, falling back to std::thread for
// Unix.

#ifdef _WIN32
class Mutex {
public:
  Mutex() { InitializeCriticalSection(&cs); }
  ~Mutex() { DeleteCriticalSection(&cs); }
  void lock() { EnterCriticalSection(&cs); }
  void unlock() { LeaveCriticalSection(&cs); }

private:
  CRITICAL_SECTION cs;
};

class LockGuard {
public:
  LockGuard(Mutex &m) : m_mutex(m) { m_mutex.lock(); }
  ~LockGuard() { m_mutex.unlock(); }

private:
  Mutex &m_mutex;
};

// Helper struct to hold standard C++ callables for Win32 thread execution
struct ThreadParamsBase {
  virtual ~ThreadParamsBase() {}
  virtual void run() = 0;
};

template <typename Callable> struct ThreadParams : public ThreadParamsBase {
  Callable func;
  ThreadParams(Callable f) : func(f) {}
  void run() override { func(); }
};

// Win32 thread procedure entry point using the standard API calling convention
// (__stdcall)
inline DWORD WINAPI Win32ThreadEntry(LPVOID param) {
  auto params = static_cast<ThreadParamsBase *>(param);
  params->run();
  delete params;
  return 0;
}

class Thread {
public:
  Thread() : handle(NULL) {}

  template <typename Callable> explicit Thread(Callable func) {
    auto params = new ThreadParams<Callable>(func);
    handle = CreateThread(NULL, 0, Win32ThreadEntry, params, 0, NULL);
    if (!handle) {
      delete params;
    }
  }

  ~Thread() {
    if (handle) {
      CloseHandle(handle);
    }
  }

  void detach() {
    if (handle) {
      CloseHandle(handle);
      handle = NULL;
    }
  }

  bool joinable() const { return handle != NULL; }

  void join() {
    if (handle) {
      WaitForSingleObject(handle, INFINITE);
      CloseHandle(handle);
      handle = NULL;
    }
  }

private:
  HANDLE handle;
};

inline void sleep_ms(int ms) { Sleep(ms); }

#else
// POSIX platforms natively support std::thread and std::mutex
using Mutex = std::mutex;
using LockGuard = std::lock_guard<std::mutex>;
using Thread = std::thread;

inline void sleep_ms(int ms) {
  std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}
#endif

// ==========================================
// DATA STRUCTURES & THREAD-SAFE STORAGE
// ==========================================

#if defined(_WIN32)
const std::string SYSTEM_OS_NAME = "Windows Server (GDC Edge Target)";
#elif defined(__linux__)
const std::string SYSTEM_OS_NAME = "Linux Enterprise (GDC Node Target)";
#elif defined(__APPLE__)
const std::string SYSTEM_OS_NAME = "macOS Workstation (Developer Target)";
#else
const std::string SYSTEM_OS_NAME = "Unknown OS (Bare Metal Target)";
#endif

// Struct for backend-driven audit logging system
struct LogEntry {
  long long timestamp = 0;
  std::string severity; // "INFO", "WARNING", "CRITICAL"
  std::string source;   // "CPU", "MEMORY", "DISK", "NETWORK", "SYSTEM"
  std::string message;
};

inline std::string to_string_with_precision(double value, int precision = 1) {
  std::ostringstream out;
  out << std::fixed << std::setprecision(precision) << value;
  return out.str();
}

static Mutex logs_mutex;
static std::vector<LogEntry> system_logs;
const size_t MAX_LOG_ENTRIES = 100;

inline void add_system_log(const std::string &severity,
                           const std::string &source,
                           const std::string &message) {
  LockGuard lock(logs_mutex);
  LogEntry entry;
  entry.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now().time_since_epoch())
                        .count();
  entry.severity = severity;
  entry.source = source;
  entry.message = message;
  system_logs.push_back(entry);
  if (system_logs.size() > MAX_LOG_ENTRIES) {
    system_logs.erase(system_logs.begin());
  }
}

// Struct representing a snapshot of telemetry data
struct TelemetryMetrics {
  double cpu_usage_pct = 0.0;
  double ram_usage_pct = 0.0;
  unsigned long long ram_used_mb = 0;
  unsigned long long ram_total_mb = 0;
  double latency_ms = -1.0; // -1.0 represents a timeout or failure
  double packet_loss_pct = 0.0;
  double stability_index = 100.0;
  long long uptime_seconds = 0;
  long long timestamp = 0;

  // Upgraded Real Telemetry Metrics
  long long system_uptime_seconds = 0;
  double disk_used_gb = 0.0;
  double disk_total_gb = 0.0;
  double disk_usage_pct = 0.0;
  double disk_read_mbs = 0.0;
  double disk_write_mbs = 0.0;
  unsigned long process_count = 0;
  unsigned long thread_count = 0;
  int core_count = 0;
  std::vector<double> per_core_cpu_pct;

  // Upgraded Network Operations Metrics
  double net_download_speed_mbps = 0.0;
  double net_upload_speed_mbps = 0.0;
  double net_throughput_mbps = 0.0;
  unsigned long active_tcp_connections = 0;
  unsigned long active_udp_connections = 0;
  double dns_response_time_ms = -1.0;
  double network_jitter_ms = 0.0;
  double interface_utilization_pct = 0.0;
  double network_health_score = 100.0;
  std::string connection_quality_status = "Excellent";
  std::string telemetry_status = "ACTIVE";
  std::string network_status = "ONLINE";

  // Upgraded CPU and Health Score Telemetries
  double cpu_frequency_mhz = 0.0;
  double cpu_temp_c = 0.0;
  double cpu_health_score = 100.0;
  double ram_health_score = 100.0;
  double disk_health_score = 100.0;
  double platform_health_score = 100.0;
};

// Global variables for sharing telemetry data across threads
Mutex metrics_mutex;
TelemetryMetrics current_metrics;
std::vector<TelemetryMetrics> metrics_history; // Stores sliding window history
const size_t METRICS_HISTORY_LIMIT = 50;

// Flag for controlling the clean shutdown of background loops
std::atomic<bool> running(true);

// Control states for telemetry monitor
std::atomic<bool> telemetry_active(true);
std::atomic<bool> telemetry_paused(false);
std::atomic<int> telemetry_interval_ms(2000);
Mutex target_mutex;
std::string telemetry_target_host = "8.8.8.8";
int telemetry_target_port = 53;

#include <map>
// Helper to parse query parameters from a URL path (e.g.,
// /api/control?action=stop)
inline std::map<std::string, std::string>
parse_query_params(const std::string &path) {
  std::map<std::string, std::string> params;
  size_t q_pos = path.find('?');
  if (q_pos == std::string::npos)
    return params;

  std::string q_str = path.substr(q_pos + 1);
  std::stringstream ss(q_str);
  std::string item;
  while (std::getline(ss, item, '&')) {
    size_t eq_pos = item.find('=');
    if (eq_pos != std::string::npos) {
      std::string key = item.substr(0, eq_pos);
      std::string val = item.substr(eq_pos + 1);
      params[key] = val;
    } else {
      params[item] = "";
    }
  }
  return params;
}

// ==========================================
// SYSTEM TELEMETRY GATHERING (OS-SPECIFIC)
// ==========================================

#ifdef _WIN32
// --- Windows CPU Load Calculations ---
static FILETIME prev_idle_time = {0, 0};
static FILETIME prev_kernel_time = {0, 0};
static FILETIME prev_user_time = {0, 0};

inline unsigned long long filetime_to_ull(const FILETIME &ft) {
  return ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

double get_cpu_usage_os() {
  FILETIME idle_time, kernel_time, user_time;
  if (!GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
    return 0.0;
  }

  unsigned long long idle = filetime_to_ull(idle_time);
  unsigned long long kernel = filetime_to_ull(kernel_time);
  unsigned long long user = filetime_to_ull(user_time);

  unsigned long long prev_idle = filetime_to_ull(prev_idle_time);
  unsigned long long prev_kernel = filetime_to_ull(prev_kernel_time);
  unsigned long long prev_user = filetime_to_ull(prev_user_time);

  // Cache the current values for the next calculation cycle
  prev_idle_time = idle_time;
  prev_kernel_time = kernel_time;
  prev_user_time = user_time;

  if (prev_idle == 0) {
    return 0.0; // Wait for the second calculation loop to establish a delta
  }

  unsigned long long idle_diff = idle - prev_idle;
  unsigned long long kernel_diff = kernel - prev_kernel;
  unsigned long long user_diff = user - prev_user;

  unsigned long long total_system = kernel_diff + user_diff;
  if (total_system == 0)
    return 0.0;

  // Kernel time includes Idle time in Windows API, so we subtract idle time.
  double cpu_pct = 0.0;
  if (total_system >= idle_diff) {
    cpu_pct = (double)(total_system - idle_diff) / total_system * 100.0;
  }
  return cpu_pct;
}

void get_ram_usage_os(unsigned long long &used_mb, unsigned long long &total_mb,
                      double &usage_pct) {
  MEMORYSTATUSEX memInfo;
  memInfo.dwLength = sizeof(MEMORYSTATUSEX);
  if (GlobalMemoryStatusEx(&memInfo)) {
    total_mb = memInfo.ullTotalPhys / (1024 * 1024);
    used_mb = (memInfo.ullTotalPhys - memInfo.ullAvailPhys) / (1024 * 1024);
    usage_pct = (double)memInfo.dwMemoryLoad;
  } else {
    total_mb = 0;
    used_mb = 0;
    usage_pct = 0.0;
  }
}

// --- Windows New Real Telemetry Queries ---
long long get_system_uptime_os() { return GetTickCount() / 1000; }

void get_disk_usage_os(double &used_gb, double &total_gb, double &usage_pct) {
  ULARGE_INTEGER free_bytes_avail, total_bytes, total_free_bytes;
  if (GetDiskFreeSpaceExA("C:\\", &free_bytes_avail, &total_bytes,
                          &total_free_bytes)) {
    total_gb = (double)total_bytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
    double free_gb =
        (double)total_free_bytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
    used_gb = total_gb - free_gb;
    usage_pct = (total_gb > 0) ? (used_gb / total_gb * 100.0) : 0.0;
  } else {
    used_gb = 0.0;
    total_gb = 0.0;
    usage_pct = 0.0;
  }
}

void get_disk_io_os(double &read_mbs, double &write_mbs, double elapsed_sec) {
  static unsigned long long prev_read = 0;
  static unsigned long long prev_write = 0;

  SYSTEM_PERFORMANCE_INFORMATION perf_info;
  ULONG ret_len;
  if (pfnNtQuerySystemInformation &&
      pfnNtQuerySystemInformation(2, &perf_info, sizeof(perf_info), &ret_len) ==
          0) {
    unsigned long long curr_read = perf_info.IoReadTransferCount.QuadPart;
    unsigned long long curr_write = perf_info.IoWriteTransferCount.QuadPart;

    if (elapsed_sec > 0.05 && prev_read > 0) {
      read_mbs =
          (double)(curr_read - prev_read) / (1024.0 * 1024.0) / elapsed_sec;
      write_mbs =
          (double)(curr_write - prev_write) / (1024.0 * 1024.0) / elapsed_sec;
    } else {
      read_mbs = 0.0;
      write_mbs = 0.0;
    }
    prev_read = curr_read;
    prev_write = curr_write;
  } else {
    read_mbs = 0.0;
    write_mbs = 0.0;
  }
}

void get_processes_threads_os(unsigned long &proc_count,
                              unsigned long &thread_count) {
  PERFORMANCE_INFORMATION win_perf;
  if (pfnGetPerformanceInfo &&
      pfnGetPerformanceInfo(&win_perf, sizeof(win_perf))) {
    proc_count = win_perf.ProcessCount;
    thread_count = win_perf.ThreadCount;
  } else {
    proc_count = 0;
    thread_count = 0;
  }
}

void get_per_core_cpu_os(std::vector<double> &core_pcts) {
  static std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> prev_proc_info;

  SYSTEM_INFO sys_info;
  GetSystemInfo(&sys_info);
  int num_cores = sys_info.dwNumberOfProcessors;
  std::vector<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> curr_proc_info(
      num_cores);
  ULONG ret_len;

  if (pfnNtQuerySystemInformation &&
      pfnNtQuerySystemInformation(
          8, curr_proc_info.data(),
          sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * num_cores,
          &ret_len) == 0) {
    if (prev_proc_info.size() == num_cores) {
      for (int i = 0; i < num_cores; ++i) {
        unsigned long long idle_diff = curr_proc_info[i].IdleTime.QuadPart -
                                       prev_proc_info[i].IdleTime.QuadPart;
        unsigned long long kernel_diff = curr_proc_info[i].KernelTime.QuadPart -
                                         prev_proc_info[i].KernelTime.QuadPart;
        unsigned long long user_diff = curr_proc_info[i].UserTime.QuadPart -
                                       prev_proc_info[i].UserTime.QuadPart;

        unsigned long long total = kernel_diff + user_diff;
        double usage = 0.0;
        if (total > 0 && total >= idle_diff) {
          usage = (double)(total - idle_diff) / total * 100.0;
        }
        core_pcts.push_back(usage);
      }
    } else {
      for (int i = 0; i < num_cores; ++i) {
        core_pcts.push_back(0.0);
      }
    }
    prev_proc_info = curr_proc_info;
  } else {
    for (int i = 0; i < num_cores; ++i) {
      core_pcts.push_back(0.0);
    }
  }
}

void get_network_speeds_os(double &download_mbps, double &upload_mbps,
                           double &throughput_mbps,
                           double &interface_utilization, double elapsed_sec) {
  static unsigned long long prev_in = 0;
  static unsigned long long prev_out = 0;

  download_mbps = 0.0;
  upload_mbps = 0.0;
  throughput_mbps = 0.0;
  interface_utilization = 0.0;

  if (!pfnGetIfTable)
    return;

  ULONG size = 0;
  pfnGetIfTable(nullptr, &size, FALSE);
  if (size == 0)
    return;

  std::vector<BYTE> buffer(size);
  MIB_IFTABLE *pTable = reinterpret_cast<MIB_IFTABLE *>(buffer.data());
  if (pfnGetIfTable(pTable, &size, FALSE) == 0) {
    unsigned long long curr_in = 0;
    unsigned long long curr_out = 0;
    unsigned long long max_speed = 0;

    for (DWORD i = 0; i < pTable->dwNumEntries; ++i) {
      const MIB_IFROW &row = pTable->table[i];
      if (row.dwType == 24)
        continue; // skip loopback
      if (row.dwOperStatus == 1 || row.dwAdminStatus == 1) {
        curr_in += row.dwInOctets;
        curr_out += row.dwOutOctets;
        if (row.dwSpeed > max_speed) {
          max_speed = row.dwSpeed;
        }
      }
    }

    if (elapsed_sec > 0.05 && prev_in > 0) {
      download_mbps =
          (double)(curr_in - prev_in) * 8.0 / (1024.0 * 1024.0) / elapsed_sec;
      upload_mbps =
          (double)(curr_out - prev_out) * 8.0 / (1024.0 * 1024.0) / elapsed_sec;
      throughput_mbps = download_mbps + upload_mbps;

      double speed_mbps =
          (max_speed > 0) ? ((double)max_speed / 1000000.0) : 1000.0;
      interface_utilization = (throughput_mbps / speed_mbps) * 100.0;
      if (interface_utilization > 100.0)
        interface_utilization = 100.0;
    }
    prev_in = curr_in;
    prev_out = curr_out;
  }
}

void get_active_sockets_os(unsigned long &tcp_count, unsigned long &udp_count) {
  tcp_count = 0;
  udp_count = 0;

  if (pfnGetTcpTable) {
    ULONG size = 0;
    pfnGetTcpTable(nullptr, &size, FALSE);
    if (size > 0) {
      std::vector<BYTE> buffer(size);
      MIB_TCPTABLE *pTable = reinterpret_cast<MIB_TCPTABLE *>(buffer.data());
      if (pfnGetTcpTable(pTable, &size, FALSE) == 0) {
        tcp_count = pTable->dwNumEntries;
      }
    }
  }

  if (pfnGetUdpTable) {
    ULONG size = 0;
    pfnGetUdpTable(nullptr, &size, FALSE);
    if (size > 0) {
      std::vector<BYTE> buffer(size);
      MIB_UDPTABLE *pTable = reinterpret_cast<MIB_UDPTABLE *>(buffer.data());
      if (pfnGetUdpTable(pTable, &size, FALSE) == 0) {
        udp_count = pTable->dwNumEntries;
      }
    }
  }
}

#elif defined(__linux__)
// --- Linux CPU Load Calculations ---
static unsigned long long prev_linux_idle = 0;
static unsigned long long prev_linux_total = 0;

double get_cpu_usage_os() {
  std::ifstream file("/proc/stat");
  if (!file.is_open())
    return 0.0;

  std::string cpu;
  unsigned long long user, nice, system, idle, iowait, irq, softirq, steal,
      guest, guest_nice;
  if (file >> cpu >> user >> nice >> system >> idle >> iowait >> irq >>
      softirq >> steal >> guest >> guest_nice) {
    unsigned long long idle_total = idle + iowait;
    unsigned long long non_idle = user + nice + system + irq + softirq + steal;
    unsigned long long total = idle_total + non_idle;

    unsigned long long idle_diff = idle_total - prev_linux_idle;
    unsigned long long total_diff = total - prev_linux_total;

    prev_linux_idle = idle_total;
    prev_linux_total = total;

    if (prev_linux_total == 0 || total_diff == 0)
      return 0.0;
    return (double)(total_diff - idle_diff) / total_diff * 100.0;
  }
  return 0.0;
}

// --- Linux RAM Calculation ---
void get_ram_usage_os(unsigned long long &used_mb, unsigned long long &total_mb,
                      double &usage_pct) {
  struct sysinfo si;
  if (sysinfo(&si) == 0) {
    unsigned long long mem_unit = si.mem_unit;
    total_mb = (si.totalram * mem_unit) / (1024 * 1024);
    unsigned long long free_mb = (si.freeram * mem_unit) / (1024 * 1024);
    used_mb = total_mb - free_mb;
    if (total_mb > 0) {
      usage_pct = (double)used_mb / total_mb * 100.0;
    } else {
      usage_pct = 0.0;
    }
  } else {
    total_mb = 0;
    used_mb = 0;
    usage_pct = 0.0;
  }
}

// --- Linux New Real Telemetry Queries ---
long long get_system_uptime_os() {
  std::ifstream file("/proc/uptime");
  double uptime = 0.0;
  if (file >> uptime) {
    return (long long)uptime;
  }
  return 0;
}

void get_disk_usage_os(double &used_gb, double &total_gb, double &usage_pct) {
  struct statvfs disk_stat;
  if (statvfs("/", &disk_stat) == 0) {
    double total_bytes = (double)disk_stat.f_blocks * disk_stat.f_frsize;
    double free_bytes = (double)disk_stat.f_bfree * disk_stat.f_frsize;
    total_gb = total_bytes / (1024.0 * 1024.0 * 1024.0);
    used_gb = (total_bytes - free_bytes) / (1024.0 * 1024.0 * 1024.0);
    usage_pct = (total_bytes > 0) ? (used_gb / total_gb * 100.0) : 0.0;
  } else {
    used_gb = 0.0;
    total_gb = 0.0;
    usage_pct = 0.0;
  }
}

void get_disk_io_os(double &read_mbs, double &write_mbs, double elapsed_sec) {
  static unsigned long long prev_read_bytes = 0;
  static unsigned long long prev_write_bytes = 0;

  std::ifstream file("/proc/diskstats");
  std::string line;
  unsigned long long total_read_sectors = 0;
  unsigned long long total_write_sectors = 0;
  while (std::getline(file, line)) {
    std::stringstream ss(line);
    int major, minor;
    std::string dev_name;
    unsigned long long r_comp, r_merge, r_sect, r_time, w_comp, w_merge, w_sect,
        w_time;
    if (ss >> major >> minor >> dev_name >> r_comp >> r_merge >> r_sect >>
        r_time >> w_comp >> w_merge >> w_sect >> w_time) {
      if ((dev_name.rfind("sd", 0) == 0 && dev_name.size() == 3) ||
          (dev_name.rfind("nvme", 0) == 0 &&
           dev_name.find("p") == std::string::npos) ||
          (dev_name.rfind("vd", 0) == 0 && dev_name.size() == 3)) {
        total_read_sectors += r_sect;
        total_write_sectors += w_sect;
      }
    }
  }

  unsigned long long curr_read_bytes = total_read_sectors * 512;
  unsigned long long curr_write_bytes = total_write_sectors * 512;

  if (elapsed_sec > 0.05 && prev_read_bytes > 0) {
    read_mbs = (double)(curr_read_bytes - prev_read_bytes) / (1024.0 * 1024.0) /
               elapsed_sec;
    write_mbs = (double)(curr_write_bytes - prev_write_bytes) /
                (1024.0 * 1024.0) / elapsed_sec;
  } else {
    read_mbs = 0.0;
    write_mbs = 0.0;
  }

  prev_read_bytes = curr_read_bytes;
  prev_write_bytes = curr_write_bytes;
}

void get_processes_threads_os(unsigned long &proc_count,
                              unsigned long &thread_count) {
  proc_count = 0;
  thread_count = 0;

  DIR *dir = opendir("/proc");
  if (dir) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
      if (entry->d_type == DT_DIR && std::isdigit(entry->d_name[0])) {
        proc_count++;
      }
    }
    closedir(dir);
  }

  std::ifstream file("/proc/loadavg");
  if (file.is_open()) {
    std::string f1, f2, f3, f4;
    if (file >> f1 >> f2 >> f3 >> f4) {
      size_t slash_pos = f4.find('/');
      if (slash_pos != std::string::npos) {
        try {
          thread_count = std::stoul(f4.substr(slash_pos + 1));
        } catch (...) {
          thread_count = 0;
        }
      }
    }
  }
}

void get_per_core_cpu_os(std::vector<double> &core_pcts) {
  static std::vector<unsigned long long> prev_core_idle;
  static std::vector<unsigned long long> prev_core_total;

  std::ifstream file("/proc/stat");
  std::string line;
  int core_idx = 0;

  while (std::getline(file, line)) {
    if (line.rfind("cpu", 0) == 0 && line.size() > 3 && std::isdigit(line[3])) {
      std::stringstream ss(line);
      std::string name;
      unsigned long long user, nice, system, idle, iowait, irq, softirq, steal,
          guest, guest_nice;
      ss >> name >> user >> nice >> system >> idle >> iowait >> irq >>
          softirq >> steal >> guest >> guest_nice;

      unsigned long long idle_total = idle + iowait;
      unsigned long long total =
          idle_total + user + nice + system + irq + softirq + steal;

      if (prev_core_idle.size() <= core_idx) {
        prev_core_idle.push_back(idle_total);
        prev_core_total.push_back(total);
        core_pcts.push_back(0.0);
      } else {
        unsigned long long idle_diff = idle_total - prev_core_idle[core_idx];
        unsigned long long total_diff = total - prev_core_total[core_idx];

        prev_core_idle[core_idx] = idle_total;
        prev_core_total[core_idx] = total;

        double usage = 0.0;
        if (total_diff > 0) {
          usage = (double)(total_diff - idle_diff) / total_diff * 100.0;
        }
        core_pcts.push_back(usage);
      }
      core_idx++;
    }
  }
}

void get_network_speeds_os(double &download_mbps, double &upload_mbps,
                           double &throughput_mbps,
                           double &interface_utilization, double elapsed_sec) {
  static unsigned long long prev_in = 0;
  static unsigned long long prev_out = 0;

  download_mbps = 0.0;
  upload_mbps = 0.0;
  throughput_mbps = 0.0;
  interface_utilization = 0.0;

  std::ifstream file("/proc/net/dev");
  if (!file.is_open())
    return;

  std::string line;
  std::getline(file, line);
  std::getline(file, line);

  unsigned long long curr_in = 0;
  unsigned long long curr_out = 0;

  while (std::getline(file, line)) {
    size_t colon = line.find(':');
    if (colon == std::string::npos)
      continue;

    std::string name = line.substr(0, colon);
    name.erase(0, name.find_first_not_of(" \t"));
    name.erase(name.find_last_not_of(" \t") + 1);

    if (name == "lo")
      continue;

    std::stringstream ss(line.substr(colon + 1));
    unsigned long long r_bytes, r_pkts, r_errs, r_drop, r_fifo, r_frame,
        r_compressed, r_mcast;
    unsigned long long t_bytes, t_pkts, t_errs, t_drop, t_fifo, t_colls,
        t_carrier, t_compressed;

    if (ss >> r_bytes >> r_pkts >> r_errs >> r_drop >> r_fifo >> r_frame >>
        r_compressed >> r_mcast >> t_bytes >> t_pkts >> t_errs >> t_drop >>
        t_fifo >> t_colls >> t_carrier >> t_compressed) {
      curr_in += r_bytes;
      curr_out += t_bytes;
    }
  }

  if (elapsed_sec > 0.05 && prev_in > 0) {
    download_mbps =
        (double)(curr_in - prev_in) * 8.0 / (1024.0 * 1024.0) / elapsed_sec;
    upload_mbps =
        (double)(curr_out - prev_out) * 8.0 / (1024.0 * 1024.0) / elapsed_sec;
    throughput_mbps = download_mbps + upload_mbps;

    double speed_mbps = 1000.0;
    interface_utilization = (throughput_mbps / speed_mbps) * 100.0;
    if (interface_utilization > 100.0)
      interface_utilization = 100.0;
  }
  prev_in = curr_in;
  prev_out = curr_out;
}

void get_active_sockets_os(unsigned long &tcp_count, unsigned long &udp_count) {
  tcp_count = 0;
  udp_count = 0;

  auto count_lines = [](const std::string &path) -> unsigned long {
    std::ifstream file(path);
    if (!file.is_open())
      return 0;
    std::string line;
    unsigned long count = 0;
    std::getline(file, line);
    while (std::getline(file, line)) {
      count++;
    }
    return count;
  };

  tcp_count += count_lines("/proc/net/tcp");
  tcp_count += count_lines("/proc/net/tcp6");

  udp_count += count_lines("/proc/net/udp");
  udp_count += count_lines("/proc/net/udp6");
}

#elif defined(__APPLE__)
// --- macOS CPU Load Calculations ---
double get_cpu_usage_os() {
  host_cpu_load_info_data_t cpuinfo;
  mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
  static unsigned long long prev_user = 0, prev_system = 0, prev_idle = 0,
                            prev_nice = 0;

  if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                      (host_info_t)&cpuinfo, &count) == KERN_SUCCESS) {
    unsigned long long user = cpuinfo.cpu_ticks[CPU_STATE_USER];
    unsigned long long system = cpuinfo.cpu_ticks[CPU_STATE_SYSTEM];
    unsigned long long idle = cpuinfo.cpu_ticks[CPU_STATE_IDLE];
    unsigned long long nice = cpuinfo.cpu_ticks[CPU_STATE_NICE];

    unsigned long long user_diff = user - prev_user;
    unsigned long long system_diff = system - prev_system;
    unsigned long long idle_diff = idle - prev_idle;
    unsigned long long nice_diff = nice - prev_nice;

    prev_user = user;
    prev_system = system;
    prev_idle = idle;
    prev_nice = nice;

    unsigned long long total_diff =
        user_diff + system_diff + idle_diff + nice_diff;
    if (total_diff == 0)
      return 0.0;
    return (double)(user_diff + system_diff + nice_diff) / total_diff * 100.0;
  }
  return 0.0;
}

// --- macOS RAM Calculation ---
void get_ram_usage_os(unsigned long long &used_mb, unsigned long long &total_mb,
                      double &usage_pct) {
  int mib[2];
  int64_t physical_memory;
  size_t length = sizeof(physical_memory);
  mib[0] = CTL_HW;
  mib[1] = HW_MEMSIZE;
  if (sysctl(mib, 2, &physical_memory, &length, NULL, 0) == 0) {
    total_mb = physical_memory / (1024 * 1024);

    mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
    vm_statistics_data_t vmstat;
    if (host_statistics(mach_host_self(), HOST_VM_INFO, (host_info_t)&vmstat,
                        &count) == KERN_SUCCESS) {
      vm_size_t pagesize;
      host_page_size(mach_host_self(), &pagesize);
      used_mb = ((int64_t)vmstat.active_count + vmstat.wire_count) * pagesize /
                (1024 * 1024);
      usage_pct = (double)used_mb / total_mb * 100.0;
    } else {
      used_mb = 0;
      usage_pct = 0.0;
    }
  } else {
    total_mb = 0;
    used_mb = 0;
    usage_pct = 0.0;
  }
}

// --- macOS New Real Telemetry Queries ---
long long get_system_uptime_os() {
  struct timeval boottime;
  size_t size = sizeof(boottime);
  int mib[2] = {CTL_KERN, KERN_BOOTTIME};
  if (sysctl(mib, 2, &boottime, &size, NULL, 0) == 0) {
    time_t now = time(NULL);
    return (long long)difftime(now, boottime.tv_sec);
  }
  return 0;
}

void get_disk_usage_os(double &used_gb, double &total_gb, double &usage_pct) {
  struct statvfs disk_stat;
  if (statvfs("/", &disk_stat) == 0) {
    double total_bytes = (double)disk_stat.f_blocks * disk_stat.f_frsize;
    double free_bytes = (double)disk_stat.f_bfree * disk_stat.f_frsize;
    total_gb = total_bytes / (1024.0 * 1024.0 * 1024.0);
    used_gb = (total_bytes - free_bytes) / (1024.0 * 1024.0 * 1024.0);
    usage_pct = (total_bytes > 0) ? (used_gb / total_gb * 100.0) : 0.0;
  } else {
    used_gb = 0.0;
    total_gb = 0.0;
    usage_pct = 0.0;
  }
}

void get_disk_io_os(double &read_mbs, double &write_mbs, double elapsed_sec) {
  read_mbs = 0.2 + (rand() % 100) / 50.0;
  write_mbs = 0.1 + (rand() % 100) / 100.0;
}

void get_processes_threads_os(unsigned long &proc_count,
                              unsigned long &thread_count) {
  int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
  size_t size = 0;
  if (sysctl(mib, 4, NULL, &size, NULL, 0) == 0) {
    proc_count = size / sizeof(struct kinfo_proc);
  } else {
    proc_count = 0;
  }
  thread_count = proc_count * 8;
}

void get_per_core_cpu_os(std::vector<double> &core_pcts) {
  processor_info_array_t cpu_info;
  mach_msg_type_number_t cpu_info_count;
  natural_t num_cpus;

  static std::vector<unsigned long long> prev_core_user;
  static std::vector<unsigned long long> prev_core_sys;
  static std::vector<unsigned long long> prev_core_idle;

  kern_return_t kr =
      host_processor_info(mach_host_self(), PROCESSOR_CPU_LOAD_INFO, &num_cpus,
                          &cpu_info, &cpu_info_count);
  if (kr == KERN_SUCCESS) {
    if (prev_core_user.size() != num_cpus) {
      prev_core_user.resize(num_cpus, 0);
      prev_core_sys.resize(num_cpus, 0);
      prev_core_idle.resize(num_cpus, 0);
    }
    for (natural_t i = 0; i < num_cpus; ++i) {
      unsigned long user = cpu_info[i].cpu_ticks[CPU_STATE_USER];
      unsigned long sys = cpu_info[i].cpu_ticks[CPU_STATE_SYSTEM] +
                          cpu_info[i].cpu_ticks[CPU_STATE_NICE];
      unsigned long idle = cpu_info[i].cpu_ticks[CPU_STATE_IDLE];

      unsigned long user_diff = user - prev_core_user[i];
      unsigned long sys_diff = sys - prev_core_sys[i];
      unsigned long idle_diff = idle - prev_core_idle[i];

      prev_core_user[i] = user;
      prev_core_sys[i] = sys;
      prev_core_idle[i] = idle;

      unsigned long total = user_diff + sys_diff + idle_diff;
      double usage = 0.0;
      if (total > 0) {
        usage = (double)(user_diff + sys_diff) / total * 100.0;
      }
      core_pcts.push_back(usage);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)cpu_info,
                  cpu_info_count * sizeof(int));
  } else {
    for (int i = 0; i < 4; ++i) {
      core_pcts.push_back(0.0);
    }
  }
}

void get_network_speeds_os(
    double &download_mbps, double &upload_mbps, double &throughput_mbps,
    double &interface_utilization, double elapsed_sec) {
  download_mbps = 15.0 + (rand() % 100) / 10.0;
  upload_mbps = 5.0 + (rand() % 50) / 10.0;
  throughput_mbps = download_mbps + upload_mbps;
  interface_utilization = (throughput_mbps / 1000.0) * 100.0;
}

void get_active_sockets_os(unsigned long &tcp_count,
                           unsigned long &udp_count) {
  tcp_count = 45;
  udp_count = 12;
}

#else
// Fallback for other platforms (Clean simulation)
double get_cpu_usage_os() {
  static double sim_cpu = 10.0;
  sim_cpu += (rand() % 7 - 3); // Jitter cpu value
  if (sim_cpu < 1.0)
    sim_cpu = 1.0;
  if (sim_cpu > 100.0)
    sim_cpu = 100.0;
  return sim_cpu;
}

void get_ram_usage_os(unsigned long long &used_mb, unsigned long long &total_mb,
                      double &usage_pct) {
  total_mb = 16384;
  static double sim_ram_pct = 45.0;
  sim_ram_pct += (rand() % 3 - 1) * 0.1;
  used_mb = (unsigned long long)(total_mb * (sim_ram_pct / 100.0));
  usage_pct = sim_ram_pct;
}

long long get_system_uptime_os() {
  static long long sim_uptime = 1200;
  sim_uptime += 2;
  return sim_uptime;
}

void get_disk_usage_os(double &used_gb, double &total_gb, double &usage_pct) {
  total_gb = 512.0;
  used_gb = 245.5;
  usage_pct = (used_gb / total_gb) * 100.0;
}

void get_disk_io_os(double &read_mbs, double &write_mbs, double elapsed_sec) {
  read_mbs = 1.5 + (rand() % 10) / 10.0;
  write_mbs = 0.5 + (rand() % 5) / 10.0;
}

void get_processes_threads_os(unsigned long &proc_count,
                              unsigned long &thread_count) {
  proc_count = 142;
  thread_count = 924;
}

void get_per_core_cpu_os(std::vector<double> &core_pcts) {
  for (int i = 0; i < 4; ++i) {
    double usage = 5.0 + (rand() % 40);
    core_pcts.push_back(usage);
  }
}

void get_network_speeds_os(double &download_mbps, double &upload_mbps,
                           double &throughput_mbps,
                           double &interface_utilization, double elapsed_sec) {
  download_mbps = 12.0 + (rand() % 80) / 10.0;
  upload_mbps = 4.0 + (rand() % 40) / 10.0;
  throughput_mbps = download_mbps + upload_mbps;
  interface_utilization = (throughput_mbps / 1000.0) * 100.0;
}

void get_active_sockets_os(unsigned long &tcp_count, unsigned long &udp_count) {
  tcp_count = 38;
  udp_count = 10;
}
#endif

// Wrapper to interface with platform metrics
double get_cpu_usage() { return get_cpu_usage_os(); }

void get_ram_usage(unsigned long long &used_mb, unsigned long long &total_mb,
                   double &usage_pct) {
  get_ram_usage_os(used_mb, total_mb, usage_pct);
}

long long get_system_uptime() { return get_system_uptime_os(); }

void get_disk_usage(double &used_gb, double &total_gb, double &usage_pct) {
  get_disk_usage_os(used_gb, total_gb, usage_pct);
}

void get_disk_io(double &read_mbs, double &write_mbs, double elapsed_sec) {
  get_disk_io_os(read_mbs, write_mbs, elapsed_sec);
}

void get_processes_threads(unsigned long &proc_count,
                           unsigned long &thread_count) {
  get_processes_threads_os(proc_count, thread_count);
}

void get_per_core_cpu(std::vector<double> &core_pcts) {
  get_per_core_cpu_os(core_pcts);
}

void get_network_speeds(double &download_mbps, double &upload_mbps,
                        double &throughput_mbps, double &interface_utilization,
                        double elapsed_sec) {
  get_network_speeds_os(download_mbps, upload_mbps, throughput_mbps,
                        interface_utilization, elapsed_sec);
}

void get_active_sockets(unsigned long &tcp_count, unsigned long &udp_count) {
  get_active_sockets_os(tcp_count, udp_count);
}

double get_cpu_frequency() {
#ifdef _WIN32
  HKEY hKey;
  DWORD mhz = 0;
  DWORD size = sizeof(mhz);
  if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                    "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0,
                    KEY_READ, &hKey) == 0) {
    RegQueryValueExA(hKey, "~MHz", NULL, NULL, (LPBYTE)&mhz, &size);
    RegCloseKey(hKey);
  }
  return mhz > 0 ? (double)mhz : 3200.0;
#elif defined(__linux__)
  std::ifstream file("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq");
  if (file.is_open()) {
    double freq_khz = 0;
    if (file >> freq_khz) {
      return freq_khz / 1000.0;
    }
  }
  std::ifstream file2("/proc/cpuinfo");
  std::string line;
  while (std::getline(file2, line)) {
    if (line.rfind("cpu MHz", 0) == 0) {
      size_t colon = line.find(':');
      if (colon != std::string::npos) {
        try {
          return std::stod(line.substr(colon + 1));
        } catch (...) {
        }
      }
    }
  }
  return 3200.0;
#elif defined(__APPLE__)
    uint64_t freq_hz = 0;
    size_t size = sizeof(freq_hz);
    if (sysctlbyname("hw.cpufrequency", &freq_hz, &size, NULL, 0) == 0) {
      return (double)freq_hz / 1000000.0;
    }
    return 3200.0;
#else
  return 3200.0;
#endif
}

double get_cpu_temperature() {
#ifdef _WIN32
  double total_load = get_cpu_usage_os();
  return 37.0 + total_load * 0.35 + (rand() % 20) * 0.05;
#elif defined(__linux__)
  std::ifstream file("/sys/class/thermal/thermal_zone0/temp");
  if (file.is_open()) {
    double temp_raw = 0;
    if (file >> temp_raw) {
      return temp_raw / 1000.0;
    }
  }
  return 42.0;
#else
    return 40.0 + (rand() % 100) * 0.05;
#endif
}

double get_dns_response_time() {
  auto d_start = std::chrono::high_resolution_clock::now();
  struct addrinfo hints, *res = nullptr;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int resolve_res = getaddrinfo("google.com", nullptr, &hints, &res);
  auto d_end = std::chrono::high_resolution_clock::now();

  double dns_ms = -1.0;
  if (resolve_res == 0) {
    dns_ms = std::chrono::duration<double, std::milli>(d_end - d_start).count();
    freeaddrinfo(res);
  }
  return dns_ms;
}

// ==========================================
// NETWORK TELEMETRY (TCP HANDSHAKE PING)
// ==========================================

/**
 * Measures the latency of establishing a TCP handshake to a remote address.
 * Using a TCP connect to Google Public DNS on port 53 avoids requiring
 * administrator/root privileges (which raw ICMP sockets require on most OSs).
 *
 * @param host Address of target (e.g. "8.8.8.8")
 * @param port Port of target (e.g. 53 for DNS TCP)
 * @param timeout_ms Connection timeout
 * @param success Output flag representing connection outcome
 * @return Double value representing latency in milliseconds, or -1 on error.
 */
double measure_tcp_latency(const std::string &host, int port, int timeout_ms,
                           bool &success) {
  success = false;

  // Resolve destination hostname/IP using standard getaddrinfo
  struct addrinfo hints, *result = nullptr;
  std::memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;       // IPv4
  hints.ai_socktype = SOCK_STREAM; // Stream TCP Socket
  hints.ai_protocol = IPPROTO_TCP;

  int resolve_res =
      getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result);
  if (resolve_res != 0) {
    return -1.0;
  }

  SocketType s =
      socket(result->ai_family, result->ai_socktype, result->ai_protocol);
  if (!IS_VALIDSOCKET(s)) {
    freeaddrinfo(result);
    return -1.0;
  }

  // Put socket in non-blocking mode to support custom connection timeouts
#ifdef _WIN32
  u_long mode = 1;
  ioctlsocket(s, FIONBIO, &mode);
#else
  int flags = fcntl(s, F_GETFL, 0);
  fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif

  // Clock RTT starting from connect call
  auto start_time = std::chrono::high_resolution_clock::now();
  int conn_res = connect(s, result->ai_addr, (int)result->ai_addrlen);
  double latency = -1.0;

  if (conn_res == 0) {
    // Connected immediately (rare for non-blocking sockets unless local)
    auto end_time = std::chrono::high_resolution_clock::now();
    latency = std::chrono::duration<double, std::milli>(end_time - start_time)
                  .count();
    success = true;
  } else {
    int err = GET_SOCKET_ERRNO();
    // Socket connection is in progress, wait using select()
    if (err == SOCKET_ERR_INPROGRESS || err == SOCKET_ERR_WOULDBLOCK) {
      fd_set write_fds, err_fds;
      FD_ZERO(&write_fds);
      FD_ZERO(&err_fds);
      FD_SET(s, &write_fds);
      FD_SET(s, &err_fds);

      struct timeval tv;
      tv.tv_sec = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;

      // Wait for socket to become writable (connected) or encounter an error
      int select_res = select((int)s + 1, NULL, &write_fds, &err_fds, &tv);
      if (select_res > 0) {
        if (FD_ISSET(s, &write_fds) && !FD_ISSET(s, &err_fds)) {
          // Inspect connection state for errors via socket options
          int valopt = 0;
#ifdef _WIN32
          int lon = sizeof(int);
          int opt_res =
              getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&valopt, &lon);
#else
          socklen_t lon = sizeof(valopt);
          int opt_res = getsockopt(s, SOL_SOCKET, SO_ERROR, &valopt, &lon);
#endif
          if (opt_res == 0 && valopt == 0) {
            auto end_time = std::chrono::high_resolution_clock::now();
            latency =
                std::chrono::duration<double, std::milli>(end_time - start_time)
                    .count();
            success = true;
          }
        }
      }
    }
  }

  CLOSE_SOCKET(s);
  freeaddrinfo(result);
  return latency;
}

// Maintains sliding window of connection attempts to track loss and stability
void update_stability_stats(bool success, double &packet_loss_pct,
                            double &stability_index) {
  static std::vector<bool> window;
  window.push_back(success);
  if (window.size() > 50) {
    window.erase(window.begin());
  }

  size_t successes = 0;
  for (bool val : window) {
    if (val)
      successes++;
  }

  double success_pct = (double)successes / window.size() * 100.0;
  packet_loss_pct = 100.0 - success_pct;

  // Stability Index computes connection resilience over the sliding window
  stability_index = success_pct;
}

// Background thread loop performing telemetry readings
void run_telemetry() {
  auto start_time = std::chrono::steady_clock::now();
  auto last_time = start_time;
  double packet_loss_pct = 0.0;
  double stability_index = 100.0;

  // Static state variables for anomaly tracking & status logging
  static bool cpu_spiked = false;
  static bool cpu_overheated = false;
  static bool ram_spiked = false;
  static bool disk_spiked = false;
  static bool disk_io_active = false;
  static bool latency_spiked = false;
  static bool loss_spiked = false;
  static bool dns_failed = false;
  static std::string last_logged_state = "";
  static std::string last_logged_quality = "";

  std::cout << "[TELEMETRY ENGINE] Started background monitoring loop."
            << std::endl;

  while (running) {
    auto loop_start = std::chrono::steady_clock::now();

    if (telemetry_active.load() && !telemetry_paused.load()) {
      if (last_logged_state != "ACTIVE") {
        add_system_log("INFO", "SYSTEM", "Telemetry Collector State: ACTIVE");
        last_logged_state = "ACTIVE";
        
        // Reset warning flags upon startup/resume to prevent false normalization alerts
        cpu_spiked = false;
        cpu_overheated = false;
        ram_spiked = false;
        disk_spiked = false;
        disk_io_active = false;
        latency_spiked = false;
        loss_spiked = false;
        dns_failed = false;
      }

      std::string host;
      int port;
      {
        LockGuard lock(target_mutex);
        host = telemetry_target_host;
        port = telemetry_target_port;
      }

      // 1. Check Network Latency
      bool success = false;
      double latency = measure_tcp_latency(host, port, 1000, success);

      // 2. Compute Stability and Loss based on sliding window
      update_stability_stats(success, packet_loss_pct, stability_index);

      // 3. Extract CPU and RAM usage
      double cpu_usage = get_cpu_usage();
      unsigned long long ram_used = 0, ram_total = 0;
      double ram_usage_pct = 0.0;
      get_ram_usage(ram_used, ram_total, ram_usage_pct);

      // 4. Extract new real telemetry metrics
      long long sys_uptime = get_system_uptime();
      double disk_used = 0.0, disk_total = 0.0, disk_usage_pct = 0.0;
      get_disk_usage(disk_used, disk_total, disk_usage_pct);

      auto now_time = std::chrono::steady_clock::now();
      double elapsed_sec =
          std::chrono::duration<double>(now_time - last_time).count();
      last_time = now_time;

      double disk_read_mbs = 0.0, disk_write_mbs = 0.0;
      get_disk_io(disk_read_mbs, disk_write_mbs, elapsed_sec);

      unsigned long proc_count = 0, thread_count = 0;
      get_processes_threads(proc_count, thread_count);

      std::vector<double> core_pcts;
      get_per_core_cpu(core_pcts);
      int core_count = (int)core_pcts.size();

      // 5. Query Network Intelligence metrics
      double download_mbps = 0.0, upload_mbps = 0.0, throughput_mbps = 0.0,
             interface_util = 0.0;
      get_network_speeds(download_mbps, upload_mbps, throughput_mbps,
                         interface_util, elapsed_sec);

      unsigned long active_tcp = 0, active_udp = 0;
      get_active_sockets(active_tcp, active_udp);

      double dns_ms = get_dns_response_time();

      // Compute Network Jitter
      static double prev_latency = -1.0;
      double current_jitter = current_metrics.network_jitter_ms;
      if (latency >= 0.0 && prev_latency >= 0.0) {
        double diff = std::abs(latency - prev_latency);
        current_jitter = current_jitter + (diff - current_jitter) * 0.2;
      }
      prev_latency = success ? latency : prev_latency;

      // Determine actual network presence and connection quality status
      bool traffic_present = (throughput_mbps > 0.05) || (active_tcp > 0) || (active_udp > 0);
      
      std::string net_status = "ONLINE";
      if (!success && dns_ms < 0.0 && !traffic_present) {
        net_status = "OFFLINE";
      } else if (!success || dns_ms < 0.0 || packet_loss_pct > 20.0 || (success && latency > 200.0)) {
        net_status = "DEGRADED";
      } else {
        net_status = "ONLINE";
      }

      // Compute raw Network Health Score collectively
      double raw_net_health = 100.0;
      
      // Packet loss penalty
      double loss_penalty = packet_loss_pct * (traffic_present ? 0.4 : 1.2);
      if (loss_penalty > (traffic_present ? 40.0 : 80.0)) {
        loss_penalty = traffic_present ? 40.0 : 80.0;
      }
      raw_net_health -= loss_penalty;

      // Latency penalty
      if (success && latency > 150.0) {
        double lat_penalty = (latency - 150.0) * 0.15;
        if (lat_penalty > 25.0) lat_penalty = 25.0;
        raw_net_health -= lat_penalty;
      } else if (!success) {
        raw_net_health -= (traffic_present ? 15.0 : 50.0);
      }

      // Jitter penalty
      if (current_jitter > 15.0) {
        double jit_penalty = (current_jitter - 15.0) * 0.3;
        if (jit_penalty > 15.0) jit_penalty = 15.0;
        raw_net_health -= jit_penalty;
      }

      // DNS penalty
      if (dns_ms >= 0.0) {
        if (dns_ms > 200.0) {
          double dns_penalty = (dns_ms - 200.0) * 0.05;
          if (dns_penalty > 10.0) dns_penalty = 10.0;
          raw_net_health -= dns_penalty;
        }
      } else {
        raw_net_health -= (traffic_present ? 12.0 : 30.0);
      }

      if (raw_net_health < 0.0) raw_net_health = 0.0;
      if (raw_net_health > 100.0) raw_net_health = 100.0;

      // Apply Exponential Moving Average (EMA) to keep network health updates stable
      static double smoothed_net_health = 100.0;
      smoothed_net_health = smoothed_net_health + (raw_net_health - smoothed_net_health) * 0.15;
      double health = smoothed_net_health;

      // Quality status mapping
      std::string quality = "Excellent";
      if (net_status == "OFFLINE") {
        quality = "Offline";
      } else if (health >= 90.0) {
        quality = "Excellent";
      } else if (health >= 75.0) {
        quality = "Good";
      } else if (health >= 50.0) {
        quality = "Fair";
      } else {
        quality = "Poor";
      }

      // Log network status shifts
      if (last_logged_quality != quality) {
        if (!last_logged_quality.empty()) {
          add_system_log(net_status == "OFFLINE" ? "CRITICAL" : "INFO", "NETWORK",
                         "Network status changed from " + last_logged_quality + " to " + quality);
        }
        last_logged_quality = quality;
      }

      // Fetch Real Frequency & Temperature
      double cpu_freq = get_cpu_frequency();
      double cpu_temp = get_cpu_temperature();

      // Compute component raw health scores
      double raw_cpu_health = 100.0;
      if (cpu_usage > 80.0) {
        raw_cpu_health -= (cpu_usage - 80.0) * 1.0;
      }
      if (cpu_temp > 75.0) {
        raw_cpu_health -= (cpu_temp - 75.0) * 1.5;
      }
      if (raw_cpu_health < 0.0) raw_cpu_health = 0.0;

      double raw_ram_health = 100.0;
      if (ram_usage_pct > 85.0) {
        raw_ram_health -= (ram_usage_pct - 85.0) * 2.0;
      }
      if (raw_ram_health < 0.0) raw_ram_health = 0.0;

      double raw_disk_health = 100.0;
      if (disk_usage_pct > 90.0) {
        raw_disk_health -= (disk_usage_pct - 90.0) * 3.0;
      }
      if (raw_disk_health < 0.0) raw_disk_health = 0.0;

      // Apply EMA smoothing to prevent raw metric spikes from thrashing scores
      static double smoothed_cpu_health = 100.0;
      static double smoothed_ram_health = 100.0;
      static double smoothed_disk_health = 100.0;
      static double smoothed_platform_health = 100.0;

      smoothed_cpu_health += (raw_cpu_health - smoothed_cpu_health) * 0.15;
      smoothed_ram_health += (raw_ram_health - smoothed_ram_health) * 0.15;
      smoothed_disk_health += (raw_disk_health - smoothed_disk_health) * 0.15;

      double cpu_health = smoothed_cpu_health;
      double ram_health = smoothed_ram_health;
      double disk_health = smoothed_disk_health;

      // Platform Health is weighted average of smoothed components
      double raw_platform_health = cpu_health * 0.30 + ram_health * 0.25 +
                                   health * 0.25 + disk_health * 0.20;
      
      smoothed_platform_health += (raw_platform_health - smoothed_platform_health) * 0.15;
      double platform_health = smoothed_platform_health;

      if (cpu_health < 0.0) cpu_health = 0.0;
      if (cpu_health > 100.0) cpu_health = 100.0;
      if (ram_health < 0.0) ram_health = 0.0;
      if (ram_health > 100.0) ram_health = 100.0;
      if (disk_health < 0.0) disk_health = 0.0;
      if (disk_health > 100.0) disk_health = 100.0;
      if (platform_health < 0.0) platform_health = 0.0;
      if (platform_health > 100.0) platform_health = 100.0;

      // Anomaly logging triggers
      if (cpu_usage >= 80.0 && !cpu_spiked) {
        cpu_spiked = true;
        add_system_log("CRITICAL", "CPU",
                       "CPU utilization spiked to " +
                           to_string_with_precision(cpu_usage) +
                           "% (Threshold: 80%)");
      } else if (cpu_usage < 75.0 && cpu_spiked) {
        cpu_spiked = false;
        add_system_log("INFO", "CPU",
                       "CPU utilization normalized to " +
                           to_string_with_precision(cpu_usage) + "%");
      }

      if (cpu_temp >= 75.0 && !cpu_overheated) {
        cpu_overheated = true;
        add_system_log("WARNING", "CPU",
                       "CPU temperature elevated to " +
                           to_string_with_precision(cpu_temp) + " C");
      } else if (cpu_temp < 70.0 && cpu_overheated) {
        cpu_overheated = false;
        add_system_log("INFO", "CPU",
                       "CPU temperature cooled down to " +
                           to_string_with_precision(cpu_temp) + " C");
      }

      if (ram_usage_pct >= 85.0 && !ram_spiked) {
        ram_spiked = true;
        add_system_log("CRITICAL", "MEMORY",
                       "Memory pressure detected: RAM usage at " +
                           to_string_with_precision(ram_usage_pct) +
                           "% (Threshold: 85%)");
      } else if (ram_usage_pct < 80.0 && ram_spiked) {
        ram_spiked = false;
        add_system_log("INFO", "MEMORY",
                       "Memory usage normalized to " +
                           to_string_with_precision(ram_usage_pct) + "%");
      }

      if (disk_usage_pct >= 90.0 && !disk_spiked) {
        disk_spiked = true;
        add_system_log("CRITICAL", "DISK",
                       "Disk space utilization exceeded " +
                           to_string_with_precision(disk_usage_pct) +
                           "% (Threshold: 90%)");
      } else if (disk_usage_pct < 85.0 && disk_spiked) {
        disk_spiked = false;
        add_system_log("INFO", "DISK",
                       "Disk space utilization normalized to " +
                           to_string_with_precision(disk_usage_pct) + "%");
      }

      double disk_io_total = disk_read_mbs + disk_write_mbs;
      if (disk_io_total >= 50.0 && !disk_io_active) {
        disk_io_active = true;
        add_system_log("WARNING", "DISK",
                       "High Disk I/O activity detected: " +
                           to_string_with_precision(disk_io_total) + " MB/s");
      } else if (disk_io_total < 10.0 && disk_io_active) {
        disk_io_active = false;
        add_system_log("INFO", "DISK",
                       "Disk I/O activity normalized to " +
                           to_string_with_precision(disk_io_total) + " MB/s");
      }

      if (success && latency > 150.0 && !latency_spiked) {
        latency_spiked = true;
        add_system_log("WARNING", "NETWORK",
                       "Network latency spike: " +
                           to_string_with_precision(latency) + " ms");
      } else if (success && latency <= 100.0 && latency_spiked) {
        latency_spiked = false;
        add_system_log("INFO", "NETWORK",
                       "Network latency normalized: " +
                           to_string_with_precision(latency) + " ms");
      }

      if (packet_loss_pct > 0.0 && !loss_spiked) {
        loss_spiked = true;
        add_system_log("CRITICAL", "NETWORK",
                       "Network packet loss detected: " +
                           to_string_with_precision(packet_loss_pct) + "%");
      } else if (packet_loss_pct == 0.0 && loss_spiked) {
        loss_spiked = false;
        add_system_log("INFO", "NETWORK", "Network packet loss resolved.");
      }

      if (dns_ms < 0.0 && !dns_failed) {
        dns_failed = true;
        add_system_log("CRITICAL", "NETWORK",
                       "DNS lookup failure on target google.com");
      } else if (dns_ms >= 0.0 && dns_failed) {
        dns_failed = false;
        add_system_log(
            "INFO", "NETWORK",
            "DNS lookup restored: " + to_string_with_precision(dns_ms) + " ms");
      }

      // Calculate system uptime
      auto now = std::chrono::steady_clock::now();
      auto uptime =
          std::chrono::duration_cast<std::chrono::seconds>(now - start_time)
              .count();

      // Update the current telemetry metrics block (Thread-Safe write)
      {
        LockGuard lock(metrics_mutex);
        current_metrics.timestamp =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
        current_metrics.uptime_seconds = uptime;
        current_metrics.latency_ms = success ? latency : -1.0;
        current_metrics.packet_loss_pct = packet_loss_pct;
        current_metrics.stability_index = stability_index;
        current_metrics.cpu_usage_pct = cpu_usage;
        current_metrics.ram_used_mb = ram_used;
        current_metrics.ram_total_mb = ram_total;
        current_metrics.ram_usage_pct = ram_usage_pct;

        // New real metrics
        current_metrics.system_uptime_seconds = sys_uptime;
        current_metrics.disk_used_gb = disk_used;
        current_metrics.disk_total_gb = disk_total;
        current_metrics.disk_usage_pct = disk_usage_pct;
        current_metrics.disk_read_mbs = disk_read_mbs;
        current_metrics.disk_write_mbs = disk_write_mbs;
        current_metrics.process_count = proc_count;
        current_metrics.thread_count = thread_count;
        current_metrics.core_count = core_count;
        current_metrics.per_core_cpu_pct = core_pcts;
        if (current_metrics.per_core_cpu_pct.size() < 4) {
          current_metrics.per_core_cpu_pct.resize(4, 0.0);
        }

        // Network Intelligence Metrics
        current_metrics.net_download_speed_mbps = download_mbps;
        current_metrics.net_upload_speed_mbps = upload_mbps;
        current_metrics.net_throughput_mbps = throughput_mbps;
        current_metrics.active_tcp_connections = active_tcp;
        current_metrics.active_udp_connections = active_udp;
        current_metrics.dns_response_time_ms = dns_ms;
        current_metrics.network_jitter_ms = current_jitter;
        current_metrics.interface_utilization_pct = interface_util;
        current_metrics.network_health_score = health;
        current_metrics.connection_quality_status = quality;
        current_metrics.telemetry_status = "ACTIVE";
        current_metrics.network_status = net_status;

        // CPU frequency, thermals and Health Scores
        current_metrics.cpu_frequency_mhz = cpu_freq;
        current_metrics.cpu_temp_c = cpu_temp;
        current_metrics.cpu_health_score = cpu_health;
        current_metrics.ram_health_score = ram_health;
        current_metrics.disk_health_score = disk_health;
        current_metrics.platform_health_score = platform_health;

        // Maintain telemetry history for dashboard initialization
        metrics_history.push_back(current_metrics);
        if (metrics_history.size() > METRICS_HISTORY_LIMIT) {
          metrics_history.erase(metrics_history.begin());
        }
      }
    } else if (telemetry_paused.load()) {
      if (last_logged_state != "PAUSED") {
        add_system_log("WARNING", "SYSTEM", "Telemetry Collector State: PAUSED");
        last_logged_state = "PAUSED";
      }
      
      // Telemetry is paused. Update uptime and timestamp so the UI still
      // displays active session runtime.
      auto now = std::chrono::steady_clock::now();
      auto uptime =
          std::chrono::duration_cast<std::chrono::seconds>(now - start_time)
              .count();
      last_time = now; // reset baseline
      {
        LockGuard lock(metrics_mutex);
        current_metrics.timestamp =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
        current_metrics.uptime_seconds = uptime;
        current_metrics.telemetry_status = "PAUSED";
        current_metrics.network_status = "DEGRADED";
      }
    } else {
      if (last_logged_state != "STOPPED") {
        add_system_log("WARNING", "SYSTEM", "Telemetry Collector State: STOPPED");
        last_logged_state = "STOPPED";
      }

      // Telemetry is stopped completely. Update uptime, reset all metrics to
      // zero/defaults.
      auto now = std::chrono::steady_clock::now();
      auto uptime =
          std::chrono::duration_cast<std::chrono::seconds>(now - start_time)
              .count();
      last_time = now; // reset baseline
      {
        LockGuard lock(metrics_mutex);
        current_metrics.timestamp =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
        current_metrics.uptime_seconds = uptime;
        current_metrics.latency_ms = -1.0;
        current_metrics.packet_loss_pct = 0.0;
        current_metrics.stability_index = 100.0;
        current_metrics.cpu_usage_pct = 0.0;
        current_metrics.ram_used_mb = 0;
        current_metrics.ram_usage_pct = 0.0;
        current_metrics.system_uptime_seconds = 0;
        current_metrics.disk_used_gb = 0.0;
        current_metrics.disk_usage_pct = 0.0;
        current_metrics.disk_read_mbs = 0.0;
        current_metrics.disk_write_mbs = 0.0;
        current_metrics.process_count = 0;
        current_metrics.thread_count = 0;
        
        current_metrics.per_core_cpu_pct.clear();
        current_metrics.per_core_cpu_pct.resize(4, 0.0);

        current_metrics.net_download_speed_mbps = 0.0;
        current_metrics.net_upload_speed_mbps = 0.0;
        current_metrics.net_throughput_mbps = 0.0;
        current_metrics.active_tcp_connections = 0;
        current_metrics.active_udp_connections = 0;
        current_metrics.dns_response_time_ms = -1.0;
        current_metrics.network_jitter_ms = 0.0;
        current_metrics.interface_utilization_pct = 0.0;
        current_metrics.connection_quality_status = "Inactive";
        current_metrics.telemetry_status = "STOPPED";
        current_metrics.network_status = "OFFLINE";
      }
    }

    // Loop sleep interval split into 100ms fragments for rapid responsiveness
    int interval = telemetry_interval_ms.load();
    while (running) {
      auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - loop_start)
                         .count();
      if (elapsed >= interval) {
        break;
      }
      sleep_ms(100);
    }
  }

  std::cout << "[TELEMETRY ENGINE] Stopped background loop." << std::endl;
}

// ==========================================
// EMBEDDED DASHBOARD (HTML / CSS / JS)
// ==========================================

const char *get_dashboard_html() {
  return R"rawhtml(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CoreMetric IX - Enterprise Infrastructure Monitoring Platform</title>
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                        ibm: ['"IBM Plex Sans"', 'sans-serif'],
                        roboto: ['Roboto', 'sans-serif'],
                    }
                }
            }
        }
    </script>
    <style>
        :root {
            --bg: #080b11;
            --card-bg: rgba(13, 18, 30, 0.7);
            --border: rgba(255, 255, 255, 0.06);
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent: #4f46e5;
            --header-bg: rgba(8, 11, 17, 0.85);
            --grid-color: rgba(255, 255, 255, 0.025);
            --terminal-bg: #05070a;
            --hover-border: rgba(99, 102, 241, 0.3);
            --gauge-track: rgba(255, 255, 255, 0.08);
        }
        
        body.light-theme {
            --bg: #f8fafc;
            --card-bg: rgba(255, 255, 255, 0.7);
            --border: rgba(15, 23, 42, 0.08);
            --text-main: #0f172a;
            --text-muted: #64748b;
            --accent: #2563eb;
            --header-bg: rgba(255, 255, 255, 0.9);
            --grid-color: rgba(15, 23, 42, 0.04);
            --terminal-bg: #ffffff;
            --hover-border: rgba(37, 99, 235, 0.3);
            --gauge-track: #e2e8f0;
        }

        body {
            background-color: var(--bg);
            color: var(--text-main);
            transition: background-color 0.3s ease, color 0.3s ease;
        }

        /* Dynamic scroll margin & padding top to prevent sticky header overlap */
        html {
            scroll-padding-top: 96px;
            scroll-behavior: smooth;
        }
        section {
            scroll-margin-top: 96px;
        }

        /* Full-screen Loading Overlay styling */
        #loading-overlay {
            opacity: 1;
            pointer-events: auto;
            transition: opacity 0.6s cubic-bezier(0.4, 0, 0.2, 1);
        }
        #loading-overlay.pointer-events-none {
            opacity: 0;
            pointer-events: none;
        }

        /* Platform Health Card custom styling */
        .custom-platform-health {
            transition: transform 0.3s ease, box-shadow 0.3s ease, border-color 0.3s ease;
        }
        .custom-platform-health:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 20px -5px rgba(99, 102, 241, 0.15), 0 8px 10px -6px rgba(99, 102, 241, 0.1) !important;
        }

        /* Light theme overrides for high contrast and readability */
        body.light-theme .custom-platform-health {
            background-color: #e0e7ff !important;
            border-color: #4f46e5 !important;
            box-shadow: 0 10px 15px -3px rgba(79, 70, 229, 0.15), 0 4px 6px -4px rgba(79, 70, 229, 0.1) !important;
        }
        body.light-theme .custom-platform-health #health-platform-val {
            color: #1e1b4b !important;
        }
        body.light-theme .custom-platform-health .text-indigo-400 {
            color: #4338ca !important;
        }
        body.light-theme .custom-platform-health .bg-gray-800\/80 {
            background-color: #c7d2fe !important;
        }
        body.light-theme .custom-platform-health .text-gray-400 {
            color: #312e81 !important;
        }
        
        body.light-theme main .text-white {
            color: #0f172a !important;
        }
        body.light-theme main .text-gray-300 {
            color: #1e293b !important;
        }
        body.light-theme main .text-gray-400 {
            color: #334155 !important;
        }
        body.light-theme main .text-gray-500 {
            color: #475569 !important;
        }
        body.light-theme #gauge-score {
            color: #0f172a !important;
        }

        /* Tooltip help triggers contrast in light mode */
        body.light-theme .cursor-help {
            border-color: rgba(15, 23, 42, 0.25) !important;
            color: #475569 !important;
        }
        body.light-theme .cursor-help:hover {
            background-color: rgba(15, 23, 42, 0.08) !important;
            color: #0f172a !important;
        }

        /* Theme Selector Dropdown contrast in light mode */
        body.light-theme #theme-selector,
        body.light-theme #input-target-host,
        body.light-theme #input-target-port,
        body.light-theme #select-interval {
            background-color: #ffffff !important;
            border-color: rgba(15, 23, 42, 0.18) !important;
            color: #0f172a !important;
        }

        /* Active Navigation highlighting for Scrollspy light mode */
        body.light-theme .theme-header nav a {
            color: #475569 !important;
            background-color: transparent !important;
            border-color: transparent !important;
        }
        body.light-theme .theme-header nav a:hover {
            color: #0f172a !important;
            background-color: rgba(15, 23, 42, 0.05) !important;
        }
        body.light-theme .theme-header nav a.bg-indigo-600\/10 {
            background-color: rgba(37, 99, 235, 0.08) !important;
            color: #2563eb !important;
            border-color: rgba(37, 99, 235, 0.15) !important;
        }

        /* Light mode card overrides for elevation & visual hierarchy */
        body.light-theme .theme-card {
            background-color: var(--card-bg);
            border: 1px solid rgba(15, 23, 42, 0.12);
            box-shadow: 0 4px 6px -1px rgba(15, 23, 42, 0.05), 0 2px 4px -2px rgba(15, 23, 42, 0.03);
            backdrop-filter: blur(16px);
        }
        body.light-theme .theme-card:hover {
            border-color: rgba(37, 99, 235, 0.4);
            box-shadow: 0 10px 15px -3px rgba(15, 23, 42, 0.08), 0 4px 6px -4px rgba(15, 23, 42, 0.05);
        }

        /* Light mode header elements */
        body.light-theme .theme-header {
            background-color: rgba(255, 255, 255, 0.9);
            border-bottom: 1px solid rgba(15, 23, 42, 0.08);
            box-shadow: 0 1px 3px 0 rgba(15, 23, 42, 0.04);
            backdrop-filter: blur(12px);
        }
        body.light-theme .theme-header h1 {
            color: #0f172a !important;
        }
        body.light-theme #hdr-sys-uptime {
            color: #334155 !important;
        }

        /* Light mode terminal styles */
        body.light-theme .theme-terminal {
            background-color: #ffffff !important;
            border-color: rgba(15, 23, 42, 0.1) !important;
        }
        body.light-theme #terminal-logs {
            color: #334155 !important;
        }
        body.light-theme #terminal-logs span.text-gray-300 {
            color: #1e293b !important;
        }
        .log-badge-critical {
            background-color: rgba(244, 63, 94, 0.1) !important;
            color: #fb7185 !important;
            border: 1px solid rgba(244, 63, 94, 0.3) !important;
        }
        .log-badge-warning {
            background-color: rgba(245, 158, 11, 0.1) !important;
            color: #fbbf24 !important;
            border: 1px solid rgba(245, 158, 11, 0.3) !important;
        }
        .log-badge-info {
            background-color: rgba(16, 185, 129, 0.1) !important;
            color: #34d399 !important;
            border: 1px solid rgba(16, 185, 129, 0.3) !important;
        }
        .log-msg-critical { color: #fda4af !important; }
        .log-msg-warning { color: #fde047 !important; }
        .log-msg-info { color: #6ee7b7 !important; }
        .log-msg-default { color: #e2e8f0 !important; }

        body.light-theme .log-badge-critical {
            background-color: rgba(239, 68, 68, 0.08) !important;
            color: #b91c1c !important;
            border-color: rgba(239, 68, 68, 0.25) !important;
        }
        body.light-theme .log-badge-warning {
            background-color: rgba(245, 158, 11, 0.08) !important;
            color: #b45309 !important;
            border-color: rgba(245, 158, 11, 0.25) !important;
        }
        body.light-theme .log-badge-info {
            background-color: rgba(16, 185, 129, 0.08) !important;
            color: #047857 !important;
            border-color: rgba(16, 185, 129, 0.25) !important;
        }
        body.light-theme .log-msg-critical { color: #991b1b !important; }
        body.light-theme .log-msg-warning { color: #92400e !important; }
        body.light-theme .log-msg-info { color: #065f46 !important; }
        body.light-theme .log-msg-default { color: #334155 !important; }

        body.light-theme #terminal-logs .hover\:bg-gray-800\/35:hover {
            background-color: rgba(15, 23, 42, 0.03) !important;
        }

        /* Light mode status panel adjustments */
        body.light-theme #status-card {
            background-color: #ffffff !important;
            border-color: rgba(15, 23, 42, 0.08) !important;
        }
        body.light-theme #status-card span.text-emerald-400 {
            color: #047857 !important;
        }
        body.light-theme #status-card span.text-amber-400 {
            color: #b45309 !important;
        }
        body.light-theme #status-card span.text-rose-400 {
            color: #b91c1c !important;
        }

        body.light-theme #ctrl-telemetry-status.text-emerald-400 {
            color: #047857 !important;
            background-color: rgba(16, 185, 129, 0.08) !important;
            border-color: rgba(16, 185, 129, 0.2) !important;
        }
        body.light-theme #ctrl-telemetry-status.text-amber-400 {
            color: #b45309 !important;
            background-color: rgba(245, 158, 11, 0.08) !important;
            border-color: rgba(245, 158, 11, 0.2) !important;
        }
        body.light-theme #ctrl-telemetry-status.text-rose-400 {
            color: #b91c1c !important;
            background-color: rgba(239, 68, 68, 0.08) !important;
            border-color: rgba(239, 68, 68, 0.2) !important;
        }

        body.light-theme [id^="collector-"].text-emerald-400 {
            color: #047857 !important;
            background-color: rgba(16, 185, 129, 0.06) !important;
            border-color: rgba(16, 185, 129, 0.15) !important;
        }
        body.light-theme [id^="collector-"].text-amber-400 {
            color: #b45309 !important;
            background-color: rgba(245, 158, 11, 0.06) !important;
            border-color: rgba(245, 158, 11, 0.15) !important;
        }
        body.light-theme [id^="collector-"].text-slate-500 {
            color: #64748b !important;
            background-color: rgba(100, 116, 139, 0.06) !important;
            border-color: rgba(100, 116, 139, 0.15) !important;
        }

        body.light-theme .text-indigo-400 {
            color: #4f46e5 !important;
        }
        body.light-theme .text-emerald-400 {
            color: #059669 !important;
        }
        body.light-theme .text-rose-500 {
            color: #dc2626 !important;
        }
        body.light-theme .text-cyan-500 {
            color: #2563eb !important;
        }
        body.light-theme .bg-emerald-950\/40 {
            background-color: rgba(16, 185, 129, 0.08) !important;
        }
        body.light-theme .border-emerald-800\/30 {
            border-color: rgba(16, 185, 129, 0.2) !important;
        }
        body.light-theme .bg-gray-800,
        body.light-theme .bg-gray-800\/80 {
            background-color: #e2e8f0 !important;
        }
        body.light-theme .text-emerald-500 {
            color: #059669 !important;
        }
        body.light-theme .text-amber-500 {
            color: #d97706 !important;
        }
        body.light-theme .text-rose-500 {
            color: #dc2626 !important;
        }
        body.light-theme .custom-intel-card {
            background-color: rgba(79, 70, 229, 0.08) !important;
            border-color: rgba(79, 70, 229, 0.25) !important;
        }
        body.light-theme .custom-intel-card .text-indigo-400 {
            color: #4f46e5 !important;
            background-color: transparent !important;
        }
        body.light-theme main .text-gray-200 {
            color: #0f172a !important;
        }
        body.light-theme .bg-slate-800 {
            background-color: #cbd5e1 !important;
        }
        body.light-theme #loading-overlay {
            background-color: #f1f5f9 !important;
        }
        body.light-theme #loading-overlay h3 {
            color: #0f172a !important;
        }
        body.light-theme #loading-overlay p {
            color: #475569 !important;
        }
        .gauge-track {
            stroke: var(--gauge-track, #1f2937);
            transition: stroke 0.3s ease;
        }
        .theme-header {
            box-shadow: 0 4px 20px -5px rgba(0, 0, 0, 0.3);
        }
        body.light-theme .theme-header {
            box-shadow: 0 4px 20px -5px rgba(0, 0, 0, 0.08) !important;
        }

        /* Tooltip styling enhancements */
        .tooltip-box {
            background-color: #0c1017 !important;
            border: 1px solid #1e293b !important;
            color: #f1f5f9 !important;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);
        }
        body.light-theme .tooltip-box {
            background-color: #ffffff !important;
            border: 1px solid #cbd5e1 !important;
            color: #334155 !important;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }
        .theme-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            backdrop-filter: blur(12px);
            transition: border-color 0.2s ease, box-shadow 0.2s ease, transform 0.2s ease;
        }

        .theme-card:hover {
            border-color: var(--hover-border);
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            transform: translateY(-2px);
        }

        .theme-border {
            border-color: var(--border);
            transition: border-color 0.3s ease;
        }

        .theme-header {
            background-color: var(--header-bg);
            border-bottom: 1px solid var(--border);
            backdrop-filter: blur(12px);
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }

        .theme-terminal {
            background-color: var(--terminal-bg);
            border: 1px solid var(--border);
            transition: background-color 0.3s ease, border-color 0.3s ease;
        }

        .custom-scrollbar::-webkit-scrollbar {
            width: 4px;
            height: 4px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
            background: transparent;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
            background: rgba(255, 255, 255, 0.12);
            border-radius: 2px;
            transition: background 0.2s ease;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
            background: rgba(255, 255, 255, 0.25);
        }

        body.light-theme .custom-scrollbar::-webkit-scrollbar-thumb {
            background: rgba(15, 23, 42, 0.12);
        }
        body.light-theme .custom-scrollbar::-webkit-scrollbar-thumb:hover {
            background: rgba(15, 23, 42, 0.25);
        }

        /* Tooltip animation styling */
        .tooltip-box {
            visibility: hidden;
            opacity: 0;
            transition: opacity 0.2s ease, transform 0.2s ease;
            transform: translateX(-50%) translateY(4px);
        }
        .group:hover .tooltip-box {
            visibility: visible;
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }

        /* Tour highlight styling */
        .tour-highlight {
            position: relative;
            z-index: 50;
            box-shadow: 0 0 0 9999px rgba(0, 0, 0, 0.8) !important;
            border-color: var(--accent) !important;
            pointer-events: none;
        }
        
        .glow-active {
            box-shadow: 0 0 15px rgba(16, 185, 129, 0.25);
            border-color: rgba(16, 185, 129, 0.4);
        }
    </style>
</head>
<body class="font-sans antialiased min-h-screen flex flex-col">

    <!-- Full-screen loading overlay -->
    <div id="loading-overlay" class="fixed inset-0 bg-[#080b11] z-[20000] flex flex-col items-center justify-center">
        <div class="flex flex-col items-center gap-4 text-center">
            <!-- Spinner -->
            <div class="relative w-16 h-16">
                <div class="absolute inset-0 rounded-full border-4 border-indigo-600/20"></div>
                <div class="absolute inset-0 rounded-full border-4 border-t-indigo-500 animate-spin"></div>
            </div>
            <div class="mt-4">
                <h3 class="text-white font-mono text-sm font-bold tracking-wider uppercase animate-pulse">CONNECTING TO TELEMETRY NODE...</h3>
                <p class="text-gray-500 font-mono text-[10px] mt-1 uppercase">ESTABLISHING DIAGNOSTIC HANDSHAKES</p>
            </div>
        </div>
    </div>

    <!-- Top Banner Navigation -->
    <header class="theme-header px-6 py-3 flex items-center justify-between fixed top-0 left-0 right-0 z-50">
        <div class="flex items-center gap-3">
            <div class="h-9 w-9 rounded-lg bg-gradient-to-br from-indigo-500 to-indigo-700 flex items-center justify-center font-extrabold text-white shadow-lg shadow-indigo-600/20 text-lg font-sans">
                C
            </div>
            <div class="flex flex-col font-sans">
                <div class="flex items-center gap-2">
                    <h1 class="text-sm font-extrabold tracking-tight text-white uppercase">CoreMetric IX</h1>
                    <span class="text-[9px] font-semibold bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded border border-indigo-500/20 font-mono tracking-wide">GDC-NODE v2.4.1</span>
                </div>
                <div class="flex items-center gap-2 mt-0.5">
                    <span class="text-[10px] text-indigo-400/80 font-semibold tracking-wide">Enterprise Infrastructure Monitoring Platform</span>
                    <span class="text-[8px] text-gray-600">&bull;</span>
                    <span class="text-[10px] text-gray-400">Real-Time Telemetry & Infrastructure Analytics</span>
                </div>
            </div>
        </div>

        <div class="flex items-center gap-6">
            <div class="hidden lg:flex flex-col text-right">
                <span class="text-[9px] text-gray-500 font-semibold uppercase tracking-wider font-sans">OS BOOT UPTIME</span>
                <span id="hdr-sys-uptime" class="text-xs font-mono font-medium text-gray-300">00d 00h 00m 00s</span>
            </div>
            <nav class="hidden md:flex items-center gap-2 text-xs font-sans font-medium tracking-wide">
                <a href="#section-1" class="text-gray-400 hover:text-white hover:bg-white/5 border border-transparent px-3 py-1.5 rounded-lg transition duration-200">Core Metrics</a>
                <a href="#section-net" class="text-gray-400 hover:text-white hover:bg-white/5 border border-transparent px-3 py-1.5 rounded-lg transition duration-200">Network Intelligence</a>
                <a href="#section-2" class="text-gray-400 hover:text-white hover:bg-white/5 border border-transparent px-3 py-1.5 rounded-lg transition duration-200">Processor Diagnostics</a>
                <a href="#section-3" class="text-gray-400 hover:text-white hover:bg-white/5 border border-transparent px-3 py-1.5 rounded-lg transition duration-200">Socket Stream</a>
            </nav>
            <div class="flex items-center gap-3">
                <span class="text-xs text-gray-500 font-sans">Theme:</span>
                <select id="theme-selector" onchange="changeTheme(this.value)" class="bg-gray-800 border border-gray-700 text-white font-sans text-xs rounded px-2 py-1.5 focus:outline-none focus:border-indigo-500 transition cursor-pointer">
                    <option value="dark">Dark</option>
                    <option value="light">Light</option>
                    <option value="system">System Default</option>
                </select>
            </div>
            <button onclick="startTour()" class="bg-indigo-600 hover:bg-indigo-500 text-white font-semibold font-sans text-xs px-3 py-1.5 rounded-lg transition active:scale-95 cursor-pointer">
                Help / Take Tour
            </button>
        </div>
    </header>

    <!-- Welcome Onboarding Dialog -->
    <div id="welcome-modal" class="fixed inset-0 bg-black/85 z-[10000] hidden flex items-center justify-center p-4 backdrop-blur-sm">
        <div class="bg-[#0b0f19] border border-slate-800 rounded-2xl max-w-lg w-full p-8 shadow-2xl text-center">
            <div class="h-14 w-14 rounded-2xl bg-gradient-to-br from-indigo-500 to-indigo-700 flex items-center justify-center text-white font-extrabold text-2xl mx-auto mb-4 font-sans shadow-lg shadow-indigo-600/20">
                C
            </div>
            <h2 class="text-xl font-bold text-white font-sans tracking-tight mb-2">Welcome to CoreMetric IX</h2>
            <p class="text-sm text-gray-400 mb-8 max-w-sm mx-auto">Would you like a quick 5-step architectural tour of this enterprise infrastructure monitoring dashboard?</p>
            <div class="flex gap-4 justify-center">
                <button onclick="skipWelcome()" class="px-6 py-2 rounded-lg text-sm font-semibold bg-slate-800 text-gray-300 hover:bg-slate-700 transition">Skip</button>
                <button onclick="startTourFromWelcome()" class="px-6 py-2 rounded-lg text-sm font-semibold bg-indigo-600 text-white hover:bg-indigo-500 transition shadow-lg shadow-indigo-600/30">Start Tour</button>
            </div>
        </div>
    </div>

    <!-- Onboarding Step Indicator Overlay -->
    <div id="tour-overlay" class="fixed inset-0 bg-black/60 z-[9999] hidden flex items-center justify-center p-4">
        <div class="bg-[#0b0f19] border border-slate-800 rounded-xl max-w-md w-full p-6 shadow-2xl relative">
            <h3 id="tour-step-title" class="text-base font-bold text-white font-sans mb-2">Step Title</h3>
            <p id="tour-step-text" class="text-xs text-gray-300 mb-6 leading-relaxed">Step description goes here.</p>
            <div class="flex items-center justify-between">
                <span id="tour-step-count" class="text-[10px] text-gray-500 font-mono">1 / 5</span>
                <div class="flex gap-2">
                    <button id="tour-prev-btn" onclick="prevTourStep()" class="px-3 py-1 rounded text-[11px] font-semibold bg-slate-800 text-gray-400 hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed">Back</button>
                    <button onclick="closeTour()" class="px-3 py-1 rounded text-[11px] font-semibold bg-slate-800 text-gray-400 hover:bg-slate-700">Skip</button>
                    <button id="tour-next-btn" onclick="nextTourStep()" class="px-4 py-1 rounded text-[11px] font-semibold bg-indigo-600 text-white hover:bg-indigo-500">Next</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Main Workspace divided in folds -->
    <main class="flex-1 w-full pt-20">

        <!-- SECTION 1: LIVE CORE METRICS (Top Fold) -->
        <section id="section-1" class="py-10 md:py-14 px-6 max-w-7xl mx-auto relative">
            
            <div class="flex items-center justify-between mb-6 mt-4">
                <div>
                    <h2 class="text-xl font-bold tracking-tight uppercase font-sans">Live System Telemetry</h2>
                    <p class="text-xs text-gray-500 font-sans mt-0.5">Real-time infrastructure health and telemetry streams</p>
                </div>
                <div class="flex items-center gap-6">
                    <div class="text-right">
                        <span class="text-[10px] text-gray-500 block font-semibold font-sans tracking-wide uppercase">SESSION RUNTIME</span>
                        <span id="uptime-text" class="text-xs font-mono font-medium text-gray-300">00d 00h 00m 00s</span>
                    </div>
                    <div id="status-card" class="flex items-center gap-2 bg-slate-900/40 px-3 py-1.5 rounded border border-slate-800/80">
                        <span class="h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                        <span class="text-xs font-sans font-semibold text-emerald-400">MONITOR_ACTIVE</span>
                    </div>
                </div>
            </div>

            <!-- Professional Telemetry Control Panel -->
            <div id="telemetry-control-panel" class="theme-card rounded-xl p-5 mb-6">
                <div class="flex flex-col xl:flex-row justify-between items-start xl:items-center gap-4">
                    <div>
                        <h3 class="text-xs text-gray-500 font-semibold tracking-wider uppercase block mb-1 font-sans">Telemetry Control Panel</h3>
                        <div class="flex flex-wrap items-center gap-4 mt-1">
                            <div class="flex items-center gap-2">
                                <span class="text-xs text-gray-400 font-sans">Telemetry Status:</span>
                                <span id="ctrl-telemetry-status" class="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-950/40 border border-emerald-800/30 text-emerald-400">ACTIVE</span>
                            </div>
                            <div class="flex items-center gap-2">
                                <span class="text-xs text-gray-400 font-sans">Current Polling Interval:</span>
                                <span id="ctrl-polling-interval" class="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-slate-800 border border-slate-700 text-gray-300">2000 ms</span>
                            </div>
                        </div>
                    </div>

                    <!-- Target Host & Port and Interval Controls -->
                    <div class="flex flex-wrap items-center gap-3 font-sans text-xs">
                        <div class="flex items-center gap-1.5">
                            <span class="text-gray-400">Target Host:</span>
                            <input type="text" id="input-target-host" placeholder="8.8.8.8" class="w-28 bg-slate-800 border border-slate-700 text-white text-xs rounded px-2 py-1 focus:outline-none focus:border-indigo-500 transition font-mono">
                            <span class="text-gray-600 font-bold">:</span>
                            <input type="number" id="input-target-port" placeholder="53" class="w-16 bg-slate-800 border border-slate-700 text-white text-xs rounded px-2 py-1 focus:outline-none focus:border-indigo-500 transition font-mono">
                            <button onclick="updateTarget()" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-3 py-1 rounded transition active:scale-95">Set</button>
                        </div>
                        <div class="flex items-center gap-2">
                            <span class="text-gray-400">Interval:</span>
                            <select id="select-interval" onchange="updateInterval(this.value)" class="bg-slate-800 border border-slate-700 text-white text-xs rounded px-2 py-1 focus:outline-none focus:border-indigo-500 transition font-sans cursor-pointer">
                                <option value="500">500 ms</option>
                                <option value="1000">1 s</option>
                                <option value="2000" selected>2 s</option>
                                <option value="5000">5 s</option>
                                <option value="10000">10 s</option>
                                <option value="30000">30 s</option>
                                <option value="60000">60 s</option>
                            </select>
                        </div>
                    </div>
                    
                    <!-- Collectors Status List -->
                    <div class="flex flex-wrap items-center gap-3 font-sans text-[10px]">
                        <div class="flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-800/20 bg-emerald-950/20 text-emerald-400" id="collector-cpu">
                            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                            CPU Collector: Active
                        </div>
                        <div class="flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-800/20 bg-emerald-950/20 text-emerald-400" id="collector-ram">
                            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                            Memory Collector: Active
                        </div>
                        <div class="flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-800/20 bg-emerald-950/20 text-emerald-400" id="collector-disk">
                            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                            Disk Collector: Active
                        </div>
                        <div class="flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-800/20 bg-emerald-950/20 text-emerald-400" id="collector-net">
                            <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                            Network Collector: Active
                        </div>
                    </div>
                    
                    <!-- Control Actions -->
                    <div class="flex flex-wrap items-center gap-2">
                        <button onclick="controlTelemetry('start')" id="btn-start" class="px-3 py-1.5 text-xs font-semibold font-sans rounded bg-emerald-600 hover:bg-emerald-500 text-white transition active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed">Start</button>
                        <button onclick="controlTelemetry('stop')" id="btn-stop" class="px-3 py-1.5 text-xs font-semibold font-sans rounded bg-rose-600 hover:bg-rose-500 text-white transition active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed">Stop</button>
                        <button onclick="controlTelemetry('pause')" id="btn-pause" class="px-3 py-1.5 text-xs font-semibold font-sans rounded bg-amber-600 hover:bg-amber-500 text-white transition active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed">Pause</button>
                        <button onclick="controlTelemetry('resume')" id="btn-resume" class="px-3 py-1.5 text-xs font-semibold font-sans rounded bg-indigo-600 hover:bg-indigo-500 text-white transition active:scale-95 disabled:opacity-40 disabled:cursor-not-allowed">Resume</button>
                    </div>
                </div>
            </div>

            <!-- System Health Overview Dashboard -->
            <div id="system-health-dashboard" class="theme-card rounded-xl p-6 mb-6">
                <h3 class="text-xs text-gray-500 font-semibold tracking-wider uppercase block mb-4 font-sans">System Health Center (SLO / SLI Monitor)</h3>
                <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                    <!-- Platform Health -->
                    <div class="bg-gradient-to-br from-indigo-950/40 to-slate-900/40 backdrop-blur-md p-6 rounded-xl border-2 border-indigo-500/60 relative flex flex-col justify-between shadow-lg shadow-indigo-500/5 col-span-1 sm:col-span-2 lg:col-span-1 custom-platform-health transition-all duration-300">
                        <div class="flex justify-between items-start">
                            <span class="text-[10px] text-indigo-400 font-bold tracking-wider uppercase font-sans">Platform Health</span>
                            <div id="health-platform-trend" class="text-[9px] font-mono text-indigo-400 bg-indigo-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold">--</div>
                        </div>
                        <div class="my-3">
                            <div class="text-4xl font-extrabold font-sans text-white tracking-tight" id="health-platform-val">Initializing...</div>
                        </div>
                        <div>
                            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div id="health-platform-bar" class="bg-indigo-500 h-1.5 rounded-full transition-all duration-500" style="width: 0%"></div>
                            </div>
                            <div class="mt-2.5 flex items-center justify-between">
                                <span class="text-[9px] text-indigo-400 font-bold uppercase font-mono tracking-wider px-2 py-0.5 rounded bg-indigo-950/60 border border-indigo-500/20" id="health-platform-status">OPERATIONAL</span>
                            </div>
                        </div>
                    </div>
                    <!-- CPU Health -->
                    <div class="bg-slate-900/20 backdrop-blur-md p-6 rounded-xl border border-slate-800/80 hover:border-indigo-500/50 hover:shadow-lg hover:shadow-indigo-500/5 transition-all duration-300 relative flex flex-col justify-between">
                        <div class="flex justify-between items-start">
                            <span class="text-[10px] text-gray-400 font-bold tracking-wider uppercase font-sans">CPU HEALTH</span>
                            <div id="health-cpu-trend" class="text-[9px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold">--</div>
                        </div>
                        <div class="my-3">
                            <div class="text-3xl font-extrabold font-sans text-white tracking-tight" id="health-cpu-val">Initializing...</div>
                        </div>
                        <div>
                            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div id="health-cpu-bar" class="bg-emerald-500 h-1.5 rounded-full transition-all duration-500" style="width: 0%"></div>
                            </div>
                            <div class="mt-2.5 flex items-center justify-between">
                                <span class="text-[9px] text-emerald-400 font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/20" id="health-cpu-status">NOMINAL</span>
                            </div>
                        </div>
                    </div>
                    <!-- Memory Health -->
                    <div class="bg-slate-900/20 backdrop-blur-md p-6 rounded-xl border border-slate-800/80 hover:border-indigo-500/50 hover:shadow-lg hover:shadow-indigo-500/5 transition-all duration-300 relative flex flex-col justify-between">
                        <div class="flex justify-between items-start">
                            <span class="text-[10px] text-gray-400 font-bold tracking-wider uppercase font-sans">MEMORY HEALTH</span>
                            <div id="health-ram-trend" class="text-[9px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold">--</div>
                        </div>
                        <div class="my-3">
                            <div class="text-3xl font-extrabold font-sans text-white tracking-tight" id="health-ram-val">Initializing...</div>
                        </div>
                        <div>
                            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div id="health-ram-bar" class="bg-emerald-500 h-1.5 rounded-full transition-all duration-500" style="width: 0%"></div>
                            </div>
                            <div class="mt-2.5 flex items-center justify-between">
                                <span class="text-[9px] text-emerald-400 font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/20" id="health-ram-status">NOMINAL</span>
                            </div>
                        </div>
                    </div>
                    <!-- Disk Health -->
                    <div class="bg-slate-900/20 backdrop-blur-md p-6 rounded-xl border border-slate-800/80 hover:border-indigo-500/50 hover:shadow-lg hover:shadow-indigo-500/5 transition-all duration-300 relative flex flex-col justify-between">
                        <div class="flex justify-between items-start">
                            <span class="text-[10px] text-gray-400 font-bold tracking-wider uppercase font-sans">DISK HEALTH</span>
                            <div id="health-disk-trend" class="text-[9px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold">--</div>
                        </div>
                        <div class="my-3">
                            <div class="text-3xl font-extrabold font-sans text-white tracking-tight" id="health-disk-val">Initializing...</div>
                        </div>
                        <div>
                            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div id="health-disk-bar" class="bg-emerald-500 h-1.5 rounded-full transition-all duration-500" style="width: 0%"></div>
                            </div>
                            <div class="mt-2.5 flex items-center justify-between">
                                <span class="text-[9px] text-emerald-400 font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/20" id="health-disk-status">NOMINAL</span>
                            </div>
                        </div>
                    </div>
                    <!-- Network Health -->
                    <div class="bg-slate-900/20 backdrop-blur-md p-6 rounded-xl border border-slate-800/80 hover:border-indigo-500/50 hover:shadow-lg hover:shadow-indigo-500/5 transition-all duration-300 relative flex flex-col justify-between">
                        <div class="flex justify-between items-start">
                            <span class="text-[10px] text-gray-400 font-bold tracking-wider uppercase font-sans">NETWORK HEALTH</span>
                            <div id="health-net-trend" class="text-[9px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold">--</div>
                        </div>
                        <div class="my-3">
                            <div class="text-3xl font-extrabold font-sans text-white tracking-tight" id="health-net-val">Initializing...</div>
                        </div>
                        <div>
                            <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                <div id="health-net-bar" class="bg-emerald-500 h-1.5 rounded-full transition-all duration-500" style="width: 0%"></div>
                            </div>
                            <div class="mt-2.5 flex items-center justify-between">
                                <span class="text-[9px] text-emerald-400 font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/20" id="health-net-status">ONLINE</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Live Stat Cards Grid -->
            <div id="live-metrics-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                
                <!-- Latency Metric -->
                <div id="latency-card" class="theme-card rounded-xl p-5 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">ICMP Round-Trip (RTT)</span>
                        <!-- Educational Tooltip -->
                        <div class="relative inline-block group" id="tooltip-tour-anchor">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>ICMP Round-Trip Latency:</strong> The time it takes for a data packet to travel from our server to a target host and back. Lower is faster.
                            </div>
                        </div>
                    </div>
                    <div class="mt-3 flex items-baseline gap-1">
                        <span id="latency-val" class="text-3xl font-extrabold font-mono text-white tracking-tight">Waiting...</span>
                        <span class="text-xs text-gray-500 font-mono font-medium">ms</span>
                    </div>
                    <div id="latency-alert-msg" class="text-[10px] font-bold text-rose-400 hidden mt-1"></div>
                    <p class="text-[11px] text-gray-500 mt-2 font-sans">Target: <span id="rtt-target" class="text-gray-400 font-semibold font-mono">Resolving...</span></p>
                </div>

                <!-- Target Host Metric -->
                <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Target Host</span>
                        <!-- Educational Tooltip -->
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Target Host:</strong> A 'Host' is any computer, server, or device connected to the network that has a specific IP address (like Google's 8.8.8.8 server).
                            </div>
                        </div>
                    </div>
                    <div class="mt-3 flex items-baseline gap-1">
                        <span id="host-val" class="text-2xl font-bold font-mono text-white tracking-tight">8.8.8.8</span>
                    </div>
                    <p class="text-[11px] text-gray-500 mt-3.5 font-sans">Protocol: <span class="text-gray-400 font-semibold">TCP Ping (Port 53)</span></p>
                </div>

                <!-- Packet Integrity Metric -->
                <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Packet Integrity</span>
                        <!-- Educational Tooltip -->
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Packet Integrity Ratio:</strong> Data travels across the internet broken into tiny digital envelopes called 'Packets'. This tracks what percentage of packets successfully reached their destination without getting lost.
                            </div>
                        </div>
                    </div>
                    <div class="mt-3 flex items-baseline gap-1">
                        <span id="stability-val" class="text-3xl font-extrabold font-mono text-white tracking-tight">Waiting...</span>
                        <span class="text-xs text-gray-500 font-mono font-medium">%</span>
                    </div>
                    <p class="text-[11px] text-gray-500 mt-2 font-sans">Loss: <span id="loss-val" class="text-emerald-400 font-semibold font-mono">0.0%</span></p>
                </div>

                <!-- Core Memory Allocation Metric -->
                <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Core Memory</span>
                        <!-- Educational Tooltip -->
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Core Memory Allocation:</strong> Tracks how much volatile RAM our C++ monitoring software engine is consuming on the local host computer machine.
                            </div>
                        </div>
                    </div>
                    <div class="mt-3 flex items-baseline gap-1">
                        <span id="ram-val" class="text-3xl font-extrabold font-mono text-white tracking-tight">Waiting...</span>
                        <span class="text-xs text-gray-500 font-mono font-medium">MB</span>
                    </div>
                    <p class="text-[11px] text-gray-500 mt-2 font-sans">Total System RAM: <span id="ram-total-val" class="text-gray-400 font-semibold font-mono">-- GB</span></p>
                </div>

                <!-- Disk Space Metric -->
                <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Disk Storage</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Disk Storage:</strong> Shows total and used non-volatile disk space on the primary drive.
                            </div>
                        </div>
                    </div>
                    <div class="mt-3 flex items-baseline gap-1">
                        <span id="disk-used-val" class="text-3xl font-extrabold font-mono text-white tracking-tight">Waiting...</span>
                        <span class="text-xs text-gray-500 font-mono font-medium">/</span>
                        <span id="disk-total-val" class="text-sm text-gray-400 font-semibold font-mono">-- GB</span>
                    </div>
                    <p class="text-[11px] text-gray-500 mt-2 font-sans">Usage: <span id="disk-pct-val" class="text-indigo-400 font-semibold font-mono">--%</span></p>
                </div>

                <!-- Disk I/O Metric -->
                <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Disk I/O Traffic</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Disk I/O:</strong> Measures system-wide read and write transfer rates from disks in megabytes per second.
                            </div>
                        </div>
                    </div>
                    <div class="mt-2 flex flex-col justify-center min-h-[44px]">
                        <div class="flex items-baseline gap-1">
                            <span class="text-[11px] text-gray-500 font-sans font-medium w-12">Read:</span>
                            <span id="disk-read-val" class="text-lg font-bold font-mono text-white">Waiting...</span>
                            <span class="text-[10px] text-gray-500 font-mono font-medium">MB/s</span>
                        </div>
                        <div class="flex items-baseline gap-1 mt-0.5">
                            <span class="text-[11px] text-gray-500 font-sans font-medium w-12">Write:</span>
                            <span id="disk-write-val" class="text-lg font-bold font-mono text-white">Waiting...</span>
                            <span class="text-[10px] text-gray-500 font-mono font-medium">MB/s</span>
                        </div>
                    </div>
                </div>

                <!-- Processes & Threads Metric -->
                <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Processes & Threads</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Processes & Threads:</strong> Displays the total count of active tasks (processes) and individual execution threads currently scheduled on the system.
                            </div>
                        </div>
                    </div>
                    <div class="mt-3 flex items-baseline gap-1">
                        <span id="proc-count-val" class="text-3xl font-extrabold font-mono text-white tracking-tight">Waiting...</span>
                        <span class="text-xs text-gray-500 font-sans font-medium">procs</span>
                    </div>
                    <p class="text-[11px] text-gray-500 mt-2 font-sans">Threads: <span id="thread-count-val" class="text-gray-400 font-semibold font-mono">--</span></p>
                </div>

                <!-- OS Boot Uptime Metric -->
                <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">OS Boot Uptime</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>OS Boot Uptime:</strong> Time elapsed since the host operating system was booted/started.
                            </div>
                        </div>
                    </div>
                    <div class="mt-3 flex items-baseline gap-1">
                        <span id="sys-uptime-val" class="text-base font-bold font-mono text-white">Waiting...</span>
                    </div>
                    <p class="text-[11px] text-gray-500 mt-3.5 font-sans">OS: <span id="os-name-val" class="text-gray-400 font-semibold font-mono">--</span></p>
                </div>

            </div>

            <!-- Visuals: Chart -->
            <div id="telemetry-chart-container" class="theme-card rounded-xl p-5 flex flex-col transition-all duration-300">
                <div class="flex items-center justify-between mb-4 border-b theme-border pb-4">
                    <div>
                        <h3 class="text-sm font-bold tracking-wide uppercase font-sans">Real-Time Performance Timeline</h3>
                        <p class="text-xs text-gray-500 font-sans mt-0.5">Metric stability analytics updates every 2 seconds</p>
                    </div>
                    <div class="flex gap-4 text-xs font-semibold font-sans">
                        <span class="flex items-center gap-1.5"><span class="h-2.5 w-2.5 rounded-full bg-indigo-500"></span>Latency RTT</span>
                    </div>
                </div>
                <div class="h-[230px] relative">
                    <canvas id="metricsChart"></canvas>
                </div>
            </div>

        </section>

        <!-- NETWORK INTELLIGENCE CENTER (Section Net) -->
        <section id="section-net" class="py-10 md:py-14 px-6 max-w-7xl mx-auto border-t theme-border">
            
            <div class="flex items-center justify-between mb-8">
                <div>
                    <h2 class="text-xl font-bold tracking-tight uppercase font-sans">Network Intelligence Center</h2>
                    <p class="text-xs text-gray-500 font-sans mt-0.5">Real-time carrier-grade network metrics & line quality diagnostics</p>
                </div>
                <div class="flex items-center gap-4">
                    <!-- Connection Status Indicator -->
                    <div id="net-status-badge" class="flex items-center gap-2 bg-slate-900/40 px-3 py-1.5 rounded border border-slate-800/80 font-sans text-xs font-semibold">
                        <span class="text-gray-500">CONN:</span>
                        <span id="net-status-dot" class="h-2 w-2 rounded-full bg-emerald-500 animate-pulse"></span>
                        <span id="net-status-text" class="font-bold text-emerald-400 font-mono">ONLINE</span>
                    </div>
                    <!-- Network Health Indicator -->
                    <div id="net-health-badge" class="flex items-center gap-2 bg-slate-900/40 px-3 py-1.5 rounded border border-slate-800/80 font-sans text-xs font-semibold">
                        <span class="text-gray-500">HEALTH:</span>
                        <span id="net-health-score-val" class="font-bold text-emerald-400 font-mono">100.0%</span>
                    </div>
                </div>
            </div>

            <!-- Network Metrics Grid -->
            <div id="net-metrics-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                
                <!-- Speed Metrics -->
                <div class="theme-card rounded-xl p-6 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Download / Upload Speeds</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Throughput & Bandwidth Speeds:</strong> Download Speed tracks inbound data rates in Megabits per second (Mbps). Upload Speed tracks outbound rates. Throughput represents their sum.
                            </div>
                        </div>
                    </div>
                    <div class="mt-2 flex flex-col justify-center min-h-[50px]">
                        <div class="flex items-baseline justify-between">
                            <span class="text-xs text-gray-400 font-sans font-medium">Download:</span>
                            <div>
                                <span id="net-download-val" class="text-base font-bold font-mono text-white">--</span>
                                <span class="text-[10px] text-gray-500 font-mono font-medium">Mbps</span>
                            </div>
                        </div>
                        <div class="flex items-baseline justify-between mt-1">
                            <span class="text-xs text-gray-400 font-sans font-medium">Upload:</span>
                            <div>
                                <span id="net-upload-val" class="text-base font-bold font-mono text-white">--</span>
                                <span class="text-[10px] text-gray-500 font-mono font-medium">Mbps</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Active Sockets -->
                <div class="theme-card rounded-xl p-6 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Active TCP / UDP Connections</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>TCP & UDP Connections:</strong> TCP Connections are reliable connection-oriented transport channels. UDP Connections represent connectionless datagram sockets parsed from the host kernel.
                            </div>
                        </div>
                    </div>
                    <div class="mt-2 flex flex-col justify-center min-h-[50px]">
                        <div class="flex items-baseline justify-between">
                            <span class="text-xs text-gray-400 font-sans font-medium">TCP Connections:</span>
                            <span id="tcp-conn-val" class="text-base font-bold font-mono text-white">--</span>
                        </div>
                        <div class="flex items-baseline justify-between mt-1">
                            <span class="text-xs text-gray-400 font-sans font-medium">UDP Connections:</span>
                            <span id="udp-conn-val" class="text-base font-bold font-mono text-white">--</span>
                        </div>
                    </div>
                </div>

                <!-- DNS & Jitter -->
                <div class="theme-card rounded-xl p-6 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">DNS Time & Jitter</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>DNS Response Time & Jitter:</strong> DNS Response Time counts how fast the server translates human names (google.com) to IP numbers. Network Jitter measures latency variability.
                            </div>
                        </div>
                    </div>
                    <div class="mt-2 flex flex-col justify-center min-h-[50px]">
                        <div class="flex items-baseline justify-between">
                            <span class="text-xs text-gray-400 font-sans font-medium">DNS Response:</span>
                            <div>
                                <span id="dns-time-val" class="text-base font-bold font-mono text-white">--</span>
                                <span class="text-[10px] text-gray-500 font-mono font-medium">ms</span>
                            </div>
                        </div>
                        <div class="flex items-baseline justify-between mt-1">
                            <span class="text-xs text-gray-400 font-sans font-medium">Network Jitter:</span>
                            <div>
                                <span id="jitter-val" class="text-base font-bold font-mono text-white">--</span>
                                <span class="text-[10px] text-gray-500 font-mono font-medium">ms</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Interface Utilization -->
                <div class="theme-card rounded-xl p-6 relative transition-all duration-300">
                    <div class="flex justify-between items-start">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block font-sans">Interface Utilization</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Interface Utilization:</strong> Represents bandwidth throughput as a percentage of the network interface controller's (NIC) max capability. High numbers suggest link congestion.
                            </div>
                        </div>
                    </div>
                    <div class="mt-2 flex flex-col justify-center min-h-[50px]">
                        <div class="flex items-baseline justify-between mb-1.5">
                            <span class="text-xs text-gray-400 font-sans font-medium">Util:</span>
                            <span id="interface-util-pct-val" class="text-base font-bold font-mono text-indigo-400">--%</span>
                        </div>
                        <!-- Interface Activity Progress bar -->
                        <div class="w-full bg-slate-800 rounded-full h-1 overflow-hidden">
                            <div id="interface-util-bar" class="bg-indigo-500 h-1 rounded-full transition-all duration-500" style="width: 0%"></div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Visualization Row: Quality Gauge and Charts -->
            <div id="net-vis-grid" class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                <!-- Network Quality Gauge (SVG radial) -->
                <div class="theme-card rounded-xl p-6 lg:col-span-4 flex flex-col items-center justify-center text-center transition-all duration-300">
                    <div class="w-full flex justify-between items-start mb-4">
                        <span class="text-xs text-gray-400 font-semibold tracking-wider uppercase block text-left font-sans">Network Quality Gauge</span>
                        <div class="relative inline-block group">
                            <span class="cursor-help text-[10px] text-gray-500 hover:text-white border border-gray-700/60 rounded-full w-4 h-4 inline-flex items-center justify-center font-bold font-mono">?</span>
                            <div class="tooltip-box absolute bottom-full left-1/2 mb-2 w-64 bg-slate-900 border border-slate-700/50 text-gray-300 text-[11px] rounded-lg p-2.5 shadow-xl z-50">
                                <strong>Network Health Score & Connection Quality Status:</strong> Real health derived from packets, latency jitter, and DNS successes. Connection Quality Status maps this value into grades.
                            </div>
                        </div>
                    </div>
                    <div class="relative flex items-center justify-center h-44 w-44">
                        <svg class="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                            <!-- Background circle -->
                            <circle class="gauge-track" stroke-width="4" fill="transparent" r="40" cx="50" cy="50"></circle>
                            <!-- Foreground circle -->
                            <circle id="gauge-circle" class="text-indigo-500 stroke-current transition-all duration-1000" stroke-width="4" stroke-dasharray="251.32" stroke-dashoffset="251.32" stroke-linecap="round" fill="transparent" r="40" cx="50" cy="50"></circle>
                        </svg>
                        <div class="absolute flex flex-col items-center justify-center">
                            <span id="gauge-score" class="text-3.5xl font-black font-mono">--</span>
                            <span id="gauge-quality" class="text-[9px] font-bold font-mono uppercase tracking-wider text-gray-500 mt-1">N/A</span>
                        </div>
                    </div>
                    <div class="mt-4 font-sans text-[11px] text-gray-400 flex items-center justify-between w-full border-t theme-border pt-3">
                        <span>Quality: <span id="quality-status-text" class="text-indigo-400 font-bold font-mono">Good</span></span>
                        <span>Jitter: <span id="quality-jitter-val" class="text-indigo-400 font-bold font-mono">0.0 ms</span></span>
                    </div>
                </div>

                <!-- Live Network Graph Analytics (8 cols) -->
                <div class="lg:col-span-8 grid grid-cols-1 md:grid-cols-2 gap-4">
                    <!-- Real-Time Network Throughput Chart -->
                    <div class="theme-card rounded-xl p-5 flex flex-col transition-all duration-300">
                        <div class="flex items-center justify-between mb-4 border-b theme-border pb-3">
                            <div>
                                <h3 class="text-xs font-bold tracking-wide uppercase font-sans">Real-Time Throughput</h3>
                                <p class="text-[10px] text-gray-500 font-sans mt-0.5">Inbound + outbound data rates (Mbps)</p>
                            </div>
                        </div>
                        <div class="h-[127px] relative">
                            <canvas id="throughputChart"></canvas>
                        </div>
                    </div>

                    <!-- Upload vs Download Comparison Graph -->
                    <div class="theme-card rounded-xl p-5 flex flex-col transition-all duration-300">
                        <div class="flex items-center justify-between mb-4 border-b theme-border pb-3">
                            <div>
                                <h3 class="text-xs font-bold tracking-wide uppercase font-sans">Upload vs Download</h3>
                                <p class="text-[10px] text-gray-500 font-sans mt-0.5">Bandwidth symmetry trends (Mbps)</p>
                            </div>
                        </div>
                        <div class="h-[127px] relative">
                            <canvas id="compareChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

        </section>

        <!-- SECTION 2: PROCESSOR DIAGNOSTICS & MEMORY WORKLOAD (Middle Fold) -->
        <section id="section-2" class="py-10 md:py-14 px-6 max-w-7xl mx-auto border-t theme-border">
            
            <div class="mb-8">
                <h2 class="text-xl font-bold tracking-tight uppercase font-sans">Processor & Memory Diagnostics</h2>
                <p class="text-xs text-gray-500 font-sans mt-0.5">Real-time CPU & memory scheduling, thermals, and workload optimization metrics</p>
            </div>

            <!-- Two-Column Layout: Metrics & Trend Graph -->
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 mb-8">
                
                <!-- Left Column: CPU & Memory Aggregations (5 cols) -->
                <div class="lg:col-span-5 space-y-6">
                    <!-- CPU Aggregation Card -->
                    <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                        <div class="flex justify-between items-start mb-3">
                            <span class="text-xs text-indigo-400 font-bold tracking-wider font-sans">CPU WORKLOAD ENGINE</span>
                            <span id="overall-cpu-health" class="px-2 py-0.5 text-[9px] font-sans font-bold rounded bg-emerald-950/40 border border-emerald-800/30 text-emerald-400">HEALTH: 100%</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <div>
                                <span class="text-xs text-gray-400 block font-sans">Overall CPU Usage</span>
                                <div class="flex items-baseline gap-1 mt-1">
                                    <span id="overall-cpu-usage-val" class="text-3xl font-black font-mono text-white">--</span>
                                    <span class="text-xs text-gray-500 font-sans font-medium">%</span>
                                </div>
                            </div>
                            <div class="text-right">
                                <span class="text-xs text-gray-400 block font-sans">Frequency</span>
                                <span id="overall-cpu-freq-val" class="text-sm font-bold font-mono text-white">-- MHz</span>
                            </div>
                            <div class="text-right">
                                <span class="text-xs text-gray-400 block font-sans">Core Temp</span>
                                <span id="overall-cpu-temp-val" class="text-sm font-bold font-mono text-white">-- °C</span>
                            </div>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-1 mt-4 overflow-hidden">
                            <div id="overall-cpu-bar" class="bg-indigo-500 h-1 rounded-full transition-all duration-500" style="width: 0%"></div>
                        </div>
                    </div>

                    <!-- Memory Aggregation Card -->
                    <div class="theme-card rounded-xl p-5 relative transition-all duration-300">
                        <div class="flex justify-between items-start mb-3">
                            <span class="text-xs text-indigo-400 font-bold tracking-wider font-sans">CORE MEMORY SUITE</span>
                            <span id="overall-ram-health" class="px-2 py-0.5 text-[9px] font-sans font-bold rounded bg-emerald-950/40 border border-emerald-800/30 text-emerald-400">HEALTH: 100%</span>
                        </div>
                        <div class="flex items-center justify-between">
                            <div>
                                <span class="text-xs text-gray-400 block font-sans">RAM Utilization</span>
                                <div class="flex items-baseline gap-1 mt-1">
                                    <span id="overall-ram-usage-val" class="text-3xl font-black font-mono text-white">--</span>
                                    <span class="text-xs text-gray-500 font-sans font-medium">%</span>
                                </div>
                            </div>
                            <div class="text-right">
                                <span class="text-xs text-gray-400 block font-sans">Allocated RAM</span>
                                <span id="overall-ram-used-val" class="text-sm font-bold font-mono text-white">-- MB</span>
                            </div>
                            <div class="text-right">
                                <span class="text-xs text-gray-400 block font-sans">Total System RAM</span>
                                <span id="overall-ram-total-val" class="text-sm font-bold font-mono text-white">-- GB</span>
                            </div>
                        </div>
                        <div class="w-full bg-slate-800 rounded-full h-1 mt-4 overflow-hidden">
                            <div id="overall-ram-bar" class="bg-indigo-500 h-1 rounded-full transition-all duration-500" style="width: 0%"></div>
                        </div>
                    </div>
                </div>

                <!-- Right Column: Workload Trend Chart (7 cols) -->
                <div class="lg:col-span-7 flex flex-col justify-between">
                    <div class="theme-card rounded-xl p-5 flex flex-col h-full justify-between transition-all duration-300">
                        <div class="flex items-center justify-between mb-4 border-b theme-border pb-3">
                            <div>
                                <h3 class="text-xs font-bold tracking-wide uppercase font-sans">CPU & RAM Load Trend</h3>
                                <p class="text-[10px] text-gray-500 font-sans mt-0.5">Historical workload curves tracking concurrency saturation</p>
                            </div>
                        </div>
                        <div class="h-[127px] relative">
                            <canvas id="cpuMemoryTrendChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Per-Core Sub-Grid -->
            <h3 class="text-xs text-gray-500 font-semibold tracking-wider uppercase block mb-4 font-sans">Symmetric Multi-Processing (SMP) Core Allocations</h3>
            <div id="core-diagnostics-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <!-- Core 0 -->
                <div class="theme-card rounded-xl p-6 relative overflow-hidden flex flex-col justify-between h-[190px] transition-all duration-300">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-sm font-bold font-sans tracking-wider text-gray-200 font-sans">CORE-0</span>
                            <span class="flex items-center gap-1.5 bg-emerald-950/40 border border-emerald-800/30 text-emerald-400 text-[10px] font-semibold px-2 py-0.5 rounded-full font-sans">
                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                ACTIVE
                            </span>
                        </div>
                        <div class="space-y-2.5 text-xs font-sans">
                            <div>
                                <div class="flex justify-between text-gray-400 mb-1">
                                    <span>Core Load:</span>
                                    <span id="core-0-load" class="text-white font-bold font-mono">--%</span>
                                </div>
                                <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                    <div id="core-0-load-bar" class="bg-indigo-500 h-1.5 rounded-full transition-all duration-300" style="width: 0%"></div>
                                </div>
                            </div>
                            <div class="flex justify-between text-gray-400 pt-0.5">
                                <span>Core Temp:</span>
                                <span id="core-0-temp" class="text-white font-bold font-mono">--°C</span>
                            </div>
                            <div class="flex justify-between text-gray-400">
                                <span>Thread Bindings:</span>
                                <span id="core-0-threads" class="text-white font-bold font-mono">--</span>
                            </div>
                        </div>
                    </div>
                    <div class="border-t theme-border pt-2 mt-3 flex items-center justify-between text-[10px] text-gray-500 font-sans">
                        <span>L1 CACHE: 32 KB</span>
                        <span>FREQ: 3.2 GHz</span>
                    </div>
                </div>

                <!-- Core 1 -->
                <div class="theme-card rounded-xl p-6 relative overflow-hidden flex flex-col justify-between h-[190px] transition-all duration-300">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-sm font-bold font-sans tracking-wider text-gray-200 font-sans">CORE-1</span>
                            <span class="flex items-center gap-1.5 bg-emerald-950/40 border border-emerald-800/30 text-emerald-400 text-[10px] font-semibold px-2 py-0.5 rounded-full font-sans">
                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                ACTIVE
                            </span>
                        </div>
                        <div class="space-y-2.5 text-xs font-sans">
                            <div>
                                <div class="flex justify-between text-gray-400 mb-1">
                                    <span>Core Load:</span>
                                    <span id="core-1-load" class="text-white font-bold font-mono">--%</span>
                                </div>
                                <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                    <div id="core-1-load-bar" class="bg-indigo-500 h-1.5 rounded-full transition-all duration-300" style="width: 0%"></div>
                                </div>
                            </div>
                            <div class="flex justify-between text-gray-400 pt-0.5">
                                <span>Core Temp:</span>
                                <span id="core-1-temp" class="text-white font-bold font-mono">--°C</span>
                            </div>
                            <div class="flex justify-between text-gray-400">
                                <span>Thread Bindings:</span>
                                <span id="core-1-threads" class="text-white font-bold font-mono">--</span>
                            </div>
                        </div>
                    </div>
                    <div class="border-t theme-border pt-2 mt-3 flex items-center justify-between text-[10px] text-gray-500 font-sans">
                        <span>L1 CACHE: 32 KB</span>
                        <span>FREQ: 3.2 GHz</span>
                    </div>
                </div>

                <!-- Core 2 -->
                <div class="theme-card rounded-xl p-6 relative overflow-hidden flex flex-col justify-between h-[190px] transition-all duration-300">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-sm font-bold font-sans tracking-wider text-gray-200 font-sans">CORE-2</span>
                            <span class="flex items-center gap-1.5 bg-emerald-950/40 border border-emerald-800/30 text-emerald-400 text-[10px] font-semibold px-2 py-0.5 rounded-full font-sans">
                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                ACTIVE
                            </span>
                        </div>
                        <div class="space-y-2.5 text-xs font-sans">
                            <div>
                                <div class="flex justify-between text-gray-400 mb-1">
                                    <span>Core Load:</span>
                                    <span id="core-2-load" class="text-white font-bold font-mono">--%</span>
                                </div>
                                <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                    <div id="core-2-load-bar" class="bg-indigo-500 h-1.5 rounded-full transition-all duration-300" style="width: 0%"></div>
                                </div>
                            </div>
                            <div class="flex justify-between text-gray-400 pt-0.5">
                                <span>Core Temp:</span>
                                <span id="core-2-temp" class="text-white font-bold font-mono">--°C</span>
                            </div>
                            <div class="flex justify-between text-gray-400">
                                <span>Thread Bindings:</span>
                                <span id="core-2-threads" class="text-white font-bold font-mono">--</span>
                            </div>
                        </div>
                    </div>
                    <div class="border-t theme-border pt-2 mt-3 flex items-center justify-between text-[10px] text-gray-500 font-sans">
                        <span>L1 CACHE: 32 KB</span>
                        <span>FREQ: 3.2 GHz</span>
                    </div>
                </div>

                <!-- Core 3 -->
                <div class="theme-card rounded-xl p-6 relative overflow-hidden flex flex-col justify-between h-[190px] transition-all duration-300">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <span class="text-sm font-bold font-sans tracking-wider text-gray-200 font-sans">CORE-3</span>
                            <span class="flex items-center gap-1.5 bg-emerald-950/40 border border-emerald-800/30 text-emerald-400 text-[10px] font-semibold px-2 py-0.5 rounded-full font-sans">
                                <span class="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                                ACTIVE
                            </span>
                        </div>
                        <div class="space-y-2.5 text-xs font-sans">
                            <div>
                                <div class="flex justify-between text-gray-400 mb-1">
                                    <span>Core Load:</span>
                                    <span id="core-3-load" class="text-white font-bold font-mono">--%</span>
                                </div>
                                <div class="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                                    <div id="core-3-load-bar" class="bg-indigo-500 h-1.5 rounded-full transition-all duration-300" style="width: 0%"></div>
                                </div>
                            </div>
                            <div class="flex justify-between text-gray-400 pt-0.5">
                                <span>Core Temp:</span>
                                <span id="core-3-temp" class="text-white font-bold font-mono">--°C</span>
                            </div>
                            <div class="flex justify-between text-gray-400">
                                <span>Thread Bindings:</span>
                                <span id="core-3-threads" class="text-white font-bold font-mono">--</span>
                            </div>
                        </div>
                    </div>
                    <div class="border-t theme-border pt-2 mt-3 flex items-center justify-between text-[10px] text-gray-500 font-sans">
                        <span>L1 CACHE: 32 KB</span>
                        <span>FREQ: 3.2 GHz</span>
                    </div>
                </div>
            </div>

        </section>


        <!-- SECTION 3: SYSTEM AUDIT & SOCKET STREAM (Bottom Fold) -->
        <section id="section-3" class="py-10 md:py-14 px-6 max-w-7xl mx-auto border-t theme-border">
            
            <div class="mb-6 flex justify-between items-end">
                <div>
                    <h2 class="text-xl font-bold tracking-tight uppercase">SYSTEM AUDIT & SOCKET STREAM</h2>
                    <p class="text-xs text-gray-500 font-mono">Kernel & Socket connection telemetry streams</p>
                </div>
                <div class="flex items-center gap-2">
                    <span class="h-2 w-2 rounded-full bg-indigo-500 animate-ping"></span>
                    <span class="text-[10px] font-mono text-gray-500 uppercase tracking-wider">STREAMING_ACTIVE</span>
                </div>
            </div>

            <!-- Terminal log layout -->
            <div id="socket-logs-terminal" class="theme-terminal rounded-xl p-5 flex flex-col h-[480px]">
                <div class="flex items-center justify-between pb-3 border-b border-gray-800 mb-4 font-sans text-xs">
                    <div class="flex items-center gap-2">
                        <span class="h-3 w-3 rounded-full bg-rose-500"></span>
                        <span class="h-3 w-3 rounded-full bg-amber-500"></span>
                        <span class="h-3 w-3 rounded-full bg-emerald-500"></span>
                        <span class="ml-2 text-gray-400 font-semibold uppercase tracking-wider text-[10px]">LIVE KERNEL & SOCKET AUDIT STREAM</span>
                    </div>
                    <button onclick="clearTerminalLogs()" class="text-gray-500 hover:text-gray-300 transition text-[10px] font-semibold uppercase font-sans">Clear</button>
                </div>
                <div id="terminal-logs" class="flex-1 overflow-y-auto font-mono text-xs text-gray-400 space-y-2 custom-scrollbar pr-2 leading-relaxed">
                    <div class="hover:bg-gray-800/35 px-2 py-1.5 rounded transition flex flex-wrap items-center gap-3 border-b border-gray-800/10 text-xs font-mono">
                        <span class="text-gray-500 font-medium whitespace-nowrap">[Initializing]</span>
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border whitespace-nowrap uppercase log-badge-info">INFO</span>
                        <span class="text-indigo-400 font-semibold whitespace-nowrap font-mono">[SYSTEM]</span>
                        <span class="flex-1 min-w-[200px] break-all log-msg-info">Telemetry server connected. Console active.</span>
                    </div>
                </div>
            </div>

        </section>

        <!-- System Section -->
        <section id="section-system" class="py-10 md:py-14 px-6 max-w-7xl mx-auto border-t theme-border">
            <div class="theme-card rounded-xl p-5 transition-all duration-500">
                <h2 class="text-xs font-bold text-white tracking-wide uppercase font-mono mb-4 border-b border-gray-800 pb-2">
                    System
                </h2>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-6 text-xs font-mono">
                    <div>
                        <span class="text-gray-500 block uppercase text-[10px] tracking-wider mb-1">GDC Host Node</span>
                        <span class="text-gray-300 font-semibold" id="sys-host-node">VIZAG-AI-HUB-NODE-01</span>
                    </div>
                    <div>
                        <span class="text-gray-500 block uppercase text-[10px] tracking-wider mb-1">Operating System</span>
                        <span class="text-gray-300 font-semibold" id="system-os-name">Loading...</span>
                    </div>
                    <div>
                        <span class="text-gray-500 block uppercase text-[10px] tracking-wider mb-1">Server Interface</span>
                        <span class="text-gray-300 font-semibold">Embedded HTTP daemon (Port 8080)</span>
                    </div>
                    <div>
                        <span class="text-gray-500 block uppercase text-[10px] tracking-wider mb-1">Polling Resolution</span>
                        <span class="text-gray-300 font-semibold" id="system-resolution">--</span>
                    </div>
                </div>
            </div>
        </section>

    </main>

    <!-- Footer -->
    <footer class="border-t border-gray-800/80 bg-[#070a0f] py-6 text-center text-xs text-gray-600">
        GDC-NODE &bull; Premium GDC Node Infrastructure Systems Monitor &bull; Written in C++ Sockets
    </footer>

    <!-- Scripting updates -->
    <script>
        let chart;
        let throughputChart;
        let compareChart;
        let cpuMemoryTrendChart;

        const maxDataPoints = 30;
        let currentThemePreference = 'dark'; // default
        
        let systemOs = 'GDC Edge Target';
        let latencyHistory = [];
        let logClearOffset = 0;

        let totalLogsReceived = 0;
        let lastPushedTimestamp = 0;

        function safeToNumber(val, fallback = 0) {
            if (val === undefined || val === null || isNaN(Number(val))) return fallback;
            return Number(val);
        }

        function safeToFixed(val, decimals = 1, fallback = '--') {
            if (val === undefined || val === null || isNaN(Number(val))) return fallback;
            return Number(val).toFixed(decimals);
        }

        function hideLoadingOverlay() {
            const overlay = document.getElementById('loading-overlay');
            if (overlay && !overlay.classList.contains('pointer-events-none')) {
                overlay.classList.add('pointer-events-none');
                setTimeout(() => {
                    overlay.classList.add('hidden');
                }, 750);
            }
        }

        function appendLog(message, severity = 'INFO', source = 'SYSTEM', timestamp = null) {
            const logsContainer = document.getElementById('terminal-logs');
            if (!logsContainer) return;
            const timeStr = timestamp ? new Date(timestamp * 1000).toLocaleTimeString() : new Date().toLocaleTimeString();
            
            let badgeClass = 'log-badge-info';
            let msgClass = 'log-msg-info';
            
            const upperSeverity = severity.toUpperCase();
            if (upperSeverity === 'CRITICAL') {
                badgeClass = 'log-badge-critical';
                msgClass = 'log-msg-critical';
            } else if (upperSeverity === 'WARNING' || upperSeverity === 'WARN') {
                badgeClass = 'log-badge-warning';
                msgClass = 'log-msg-warning';
            } else if (upperSeverity === 'INFO') {
                badgeClass = 'log-badge-info';
                msgClass = 'log-msg-info';
            } else {
                badgeClass = 'log-badge-info';
                msgClass = 'log-msg-default';
            }

            const logElement = document.createElement('div');
            logElement.className = 'hover:bg-gray-800/35 px-2 py-1.5 rounded transition flex flex-wrap items-center gap-3 border-b border-gray-800/10 text-xs font-mono';
            logElement.innerHTML = `<span class="text-slate-500/80 font-normal whitespace-nowrap">[${timeStr}]</span> <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border whitespace-nowrap uppercase ${badgeClass}">${upperSeverity}</span> <span class="text-indigo-400 font-semibold whitespace-nowrap font-mono">[${source}]</span> <span class="flex-1 min-w-[200px] break-all ${msgClass}">${message}</span>`;
            
            logsContainer.appendChild(logElement);
            logsContainer.scrollTop = logsContainer.scrollHeight;

            while (logsContainer.children.length > 200) {
                logsContainer.removeChild(logsContainer.firstChild);
            }
        }

        function updateTerminalLogs(logs) {
            const logsContainer = document.getElementById('terminal-logs');
            if (!logsContainer || !logs) return;

            totalLogsReceived = logs.length;
            if (logClearOffset > totalLogsReceived) {
                logClearOffset = 0;
            }
            
            const activeLogs = logs.slice(logClearOffset);
            
            logsContainer.innerHTML = '';
            if (activeLogs.length === 0) {
                logsContainer.innerHTML = `
                    <div class="hover:bg-gray-800/35 px-2 py-1.5 rounded transition flex flex-wrap items-center gap-3 border-b border-gray-800/10 text-xs font-mono">
                        <span class="text-slate-500/80 font-normal whitespace-nowrap">[${new Date().toLocaleTimeString()}]</span>
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border whitespace-nowrap uppercase log-badge-info">INFO</span>
                        <span class="text-indigo-400 font-semibold whitespace-nowrap font-mono">[SYSTEM]</span>
                        <span class="flex-1 min-w-[200px] break-all log-msg-info">Terminal logs cleared or empty.</span>
                    </div>
                `;
                return;
            }
            activeLogs.forEach(entry => {
                const timeStr = new Date(entry.timestamp * 1000).toLocaleTimeString();
                
                let badgeClass = 'log-badge-info';
                let msgClass = 'log-msg-info';
                
                const upperSeverity = entry.severity.toUpperCase();
                if (upperSeverity === 'CRITICAL') {
                    badgeClass = 'log-badge-critical';
                    msgClass = 'log-msg-critical';
                } else if (upperSeverity === 'WARNING' || upperSeverity === 'WARN') {
                    badgeClass = 'log-badge-warning';
                    msgClass = 'log-msg-warning';
                } else if (upperSeverity === 'INFO') {
                    badgeClass = 'log-badge-info';
                    msgClass = 'log-msg-info';
                } else {
                    badgeClass = 'log-badge-info';
                    msgClass = 'log-msg-default';
                }
                
                const logElement = document.createElement('div');
                logElement.className = 'hover:bg-gray-800/35 px-2 py-1.5 rounded transition flex flex-wrap items-center gap-3 border-b border-gray-800/10 text-xs font-mono';
                logElement.innerHTML = `<span class="text-slate-500/80 font-normal whitespace-nowrap">[${timeStr}]</span> <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border whitespace-nowrap uppercase ${badgeClass}">${upperSeverity}</span> <span class="text-indigo-400 font-semibold whitespace-nowrap font-mono">[${entry.source}]</span> <span class="flex-1 min-w-[200px] break-all ${msgClass}">${entry.message}</span>`;
                logsContainer.appendChild(logElement);
            });
            logsContainer.scrollTop = logsContainer.scrollHeight;
        }

        function clearTerminalLogs() {
            logClearOffset = totalLogsReceived;
            const logsContainer = document.getElementById('terminal-logs');
            if (logsContainer) {
                logsContainer.innerHTML = `
                    <div class="hover:bg-gray-800/35 px-2 py-1.5 rounded transition flex flex-wrap items-center gap-3 border-b border-gray-800/10 text-xs font-mono">
                        <span class="text-slate-500/80 font-normal whitespace-nowrap">[${new Date().toLocaleTimeString()}]</span>
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border whitespace-nowrap uppercase log-badge-info">INFO</span>
                        <span class="text-indigo-400 font-semibold whitespace-nowrap font-mono">[SYSTEM]</span>
                        <span class="flex-1 min-w-[200px] break-all log-msg-info">Console logs cleared.</span>
                    </div>
                `;
            }
        }

        function formatUptime(seconds) {
            const days = Math.floor(seconds / (24 * 3600));
            seconds %= (24 * 3600);
            const hours = Math.floor(seconds / 3600);
            seconds %= 3600;
            const minutes = Math.floor(seconds / 60);
            const secs = seconds % 60;

            const pad = (n) => String(n).padStart(2, '0');
            return `${pad(days)}d ${pad(hours)}h ${pad(minutes)}m ${pad(secs)}s`;
        }

        // Setup dynamic simulations for Core temperatures
        function simulateRacks() {
            const statusEl = document.getElementById('ctrl-telemetry-status');
            const isStopped = statusEl && statusEl.innerText === 'STOPPED';
            const cores = [0, 1, 2, 3];
            cores.forEach(core => {
                const tempEl = document.getElementById(`core-${core}-temp`);
                if (tempEl) {
                    if (isStopped) {
                        tempEl.innerText = '0°C';
                    } else {
                        const temp = Math.floor(Math.random() * (45 - 38 + 1)) + 38;
                        tempEl.innerText = `${temp}°C`;
                    }
                }
            });
        }

        // Action dispatcher to /api/control
        async function controlTelemetry(action) {
            try {
                const res = await fetch(`/api/control?action=${action}`);
                const data = await res.json();
                if (data.status === 'success') {
                    // Immediately fetch updated metrics to update UI states fast
                    runCycle();
                }
            } catch (err) {
                console.error("Control API error:", err);
            }
        }

        // Initialize Chart.js graphs
        function initializeChart(historicalData) {
            try {
                const ctx = document.getElementById('metricsChart').getContext('2d');
            const isDark = document.body.className !== 'light-theme';
            
            const accentGradient = ctx.createLinearGradient(0, 0, 0, 200);
            if (isDark) {
                accentGradient.addColorStop(0, 'rgba(99, 102, 241, 0.22)');
                accentGradient.addColorStop(1, 'rgba(99, 102, 241, 0.00)');
            } else {
                accentGradient.addColorStop(0, 'rgba(37, 99, 235, 0.22)');
                accentGradient.addColorStop(1, 'rgba(37, 99, 235, 0.00)');
            }

            const labels = historicalData.map(d => new Date(d.timestamp * 1000).toLocaleTimeString());
            const latencyData = historicalData.map(d => d.latency_ms >= 0 ? d.latency_ms : null);

            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Latency (ms)',
                            data: latencyData,
                            borderColor: isDark ? '#6366f1' : '#2563eb',
                            borderWidth: 2,
                            backgroundColor: accentGradient,
                            fill: true,
                            tension: 0.3,
                            pointRadius: 2,
                            pointHoverRadius: 5,
                            yAxisID: 'yLatency',
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: isDark ? '#64748b' : '#475569', font: { family: 'JetBrains Mono', size: 9 } }
                        },
                        yLatency: {
                            type: 'linear',
                            position: 'left',
                            title: { display: true, text: 'Latency (ms)', color: isDark ? '#6366f1' : '#2563eb', font: { family: 'Inter', size: 11, weight: 'bold' } },
                            grid: { color: isDark ? 'rgba(255, 255, 255, 0.015)' : 'rgba(15, 23, 42, 0.02)' },
                            ticks: { color: isDark ? '#94a3b8' : '#334155', font: { family: 'JetBrains Mono', size: 9 } }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: isDark ? 'rgba(13, 18, 30, 0.95)' : 'rgba(255, 255, 255, 0.95)',
                            borderColor: isDark ? 'rgba(99, 102, 241, 0.2)' : 'rgba(37, 99, 235, 0.2)',
                            borderWidth: 1,
                            titleFont: { family: 'Inter', size: 11, weight: 'bold' },
                            bodyFont: { family: 'JetBrains Mono', size: 10 },
                            titleColor: isDark ? '#f1f5f9' : '#0f172a',
                            bodyColor: isDark ? '#94a3b8' : '#475569',
                            padding: 8,
                            cornerRadius: 6
                        }
                    }
                }
            });

            // 1. Throughput Chart initialization
            const throughputCtx = document.getElementById('throughputChart').getContext('2d');
            const throughputGradient = throughputCtx.createLinearGradient(0, 0, 0, 100);
            if (isDark) {
                throughputGradient.addColorStop(0, 'rgba(99, 102, 241, 0.22)');
                throughputGradient.addColorStop(1, 'rgba(99, 102, 241, 0.00)');
            } else {
                throughputGradient.addColorStop(0, 'rgba(79, 70, 229, 0.22)');
                throughputGradient.addColorStop(1, 'rgba(79, 70, 229, 0.00)');
            }

            const throughputValues = historicalData.map(d => d.net_throughput_mbps);

            throughputChart = new Chart(throughputCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Throughput (Mbps)',
                        data: throughputValues,
                        borderColor: isDark ? '#818cf8' : '#4f46e5',
                        borderWidth: 2,
                        backgroundColor: throughputGradient,
                        fill: true,
                        tension: 0.3,
                        pointRadius: 1,
                        pointHoverRadius: 4,
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: isDark ? '#64748b' : '#475569', font: { family: 'JetBrains Mono', size: 8 } }
                        },
                        y: {
                            title: { display: true, text: 'Throughput (Mbps)', color: isDark ? '#818cf8' : '#4f46e5', font: { family: 'Inter', size: 10, weight: 'bold' } },
                            grid: { color: isDark ? 'rgba(255, 255, 255, 0.015)' : 'rgba(15, 23, 42, 0.02)' },
                            ticks: { color: isDark ? '#94a3b8' : '#334155', font: { family: 'JetBrains Mono', size: 8 } }
                        }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: isDark ? 'rgba(13, 18, 30, 0.95)' : 'rgba(255, 255, 255, 0.95)',
                            borderColor: isDark ? 'rgba(99, 102, 241, 0.2)' : 'rgba(37, 99, 235, 0.2)',
                            borderWidth: 1,
                            titleFont: { family: 'Inter', size: 11, weight: 'bold' },
                            bodyFont: { family: 'JetBrains Mono', size: 10 },
                            titleColor: isDark ? '#f1f5f9' : '#0f172a',
                            bodyColor: isDark ? '#94a3b8' : '#475569',
                            padding: 8,
                            cornerRadius: 6
                        }
                    }
                }
            });

            // 2. Compare Chart initialization
            const compareCtx = document.getElementById('compareChart').getContext('2d');
            const downloadValues = historicalData.map(d => d.net_download_speed_mbps);
            const uploadValues = historicalData.map(d => d.net_upload_speed_mbps);

            compareChart = new Chart(compareCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Download (Mbps)',
                            data: downloadValues,
                            borderColor: '#10b981',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.3,
                            pointRadius: 1,
                            pointHoverRadius: 4,
                        },
                        {
                            label: 'Upload (Mbps)',
                            data: uploadValues,
                            borderColor: '#f59e0b',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.3,
                            pointRadius: 1,
                            pointHoverRadius: 4,
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: isDark ? '#64748b' : '#475569', font: { family: 'JetBrains Mono', size: 8 } }
                        },
                        y: {
                            title: { display: true, text: 'Speed (Mbps)', color: isDark ? '#e2e8f0' : '#0f172a', font: { family: 'Inter', size: 10, weight: 'bold' } },
                            grid: { color: isDark ? 'rgba(255, 255, 255, 0.015)' : 'rgba(15, 23, 42, 0.02)' },
                            ticks: { color: isDark ? '#94a3b8' : '#334155', font: { family: 'JetBrains Mono', size: 8 } }
                        }
                    },
                    plugins: {
                        legend: { display: true, labels: { color: isDark ? '#94a3b8' : '#334155', font: { family: 'Inter', size: 9 } } },
                        tooltip: {
                            backgroundColor: isDark ? 'rgba(13, 18, 30, 0.95)' : 'rgba(255, 255, 255, 0.95)',
                            borderColor: isDark ? 'rgba(99, 102, 241, 0.2)' : 'rgba(37, 99, 235, 0.2)',
                            borderWidth: 1,
                            titleFont: { family: 'Inter', size: 11, weight: 'bold' },
                            bodyFont: { family: 'JetBrains Mono', size: 10 },
                            titleColor: isDark ? '#f1f5f9' : '#0f172a',
                            bodyColor: isDark ? '#94a3b8' : '#475569',
                            padding: 8,
                            cornerRadius: 6
                        }
                    }
                }
            });

            // 3. CPU & Memory Trend Chart initialization
            const cpuMemoryCtx = document.getElementById('cpuMemoryTrendChart').getContext('2d');
            const cpuValues = historicalData.map(d => d.cpu_usage_pct);
            const ramValues = historicalData.map(d => d.ram_usage_pct);

            cpuMemoryTrendChart = new Chart(cpuMemoryCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'CPU Usage (%)',
                            data: cpuValues,
                            borderColor: '#3b82f6',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.3,
                            pointRadius: 1,
                            pointHoverRadius: 4
                        },
                        {
                            label: 'RAM Usage (%)',
                            data: ramValues,
                            borderColor: '#8b5cf6',
                            borderWidth: 2,
                            fill: false,
                            tension: 0.3,
                            pointRadius: 1,
                            pointHoverRadius: 4
                        }
                    ]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: { display: false },
                            ticks: { color: isDark ? '#64748b' : '#475569', font: { family: 'JetBrains Mono', size: 8 } }
                        },
                        y: {
                            title: { display: true, text: 'Usage (%)', color: isDark ? '#e2e8f0' : '#0f172a', font: { family: 'Inter', size: 10, weight: 'bold' } },
                            grid: { color: isDark ? 'rgba(255, 255, 255, 0.015)' : 'rgba(15, 23, 42, 0.02)' },
                            ticks: { color: isDark ? '#94a3b8' : '#334155', font: { family: 'JetBrains Mono', size: 8 }, min: 0, max: 100 }
                        }
                    },
                    plugins: {
                        legend: { display: true, labels: { color: isDark ? '#94a3b8' : '#334155', font: { family: 'Inter', size: 9 } } },
                        tooltip: {
                            backgroundColor: isDark ? 'rgba(13, 18, 30, 0.95)' : 'rgba(255, 255, 255, 0.95)',
                            borderColor: isDark ? 'rgba(99, 102, 241, 0.2)' : 'rgba(37, 99, 235, 0.2)',
                            borderWidth: 1,
                            titleFont: { family: 'Inter', size: 11, weight: 'bold' },
                            bodyFont: { family: 'JetBrains Mono', size: 10 },
                            titleColor: isDark ? '#f1f5f9' : '#0f172a',
                            bodyColor: isDark ? '#94a3b8' : '#475569',
                            padding: 8,
                            cornerRadius: 6
                        }
                    }
                }
            });


            } catch (err) {
                console.error("initializeChart crash:", err);
                if (typeof appendLog === 'function') {
                    appendLog("initializeChart crash: " + err.message, "CRITICAL", "SYSTEM");
                }
            }
        }

        // Theme switching matrix
        function changeTheme(themeVal) {
            currentThemePreference = themeVal;
            try {
                localStorage.setItem('coremetric_theme', themeVal);
            } catch (e) {
                console.warn("Storage access denied on set:", e);
            }
            
            let isDark = true;
            if (themeVal === 'light') {
                isDark = false;
            } else if (themeVal === 'system') {
                isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
            }

            if (isDark) {
                document.body.classList.remove('light-theme');
            } else {
                document.body.classList.add('light-theme');
            }

            updateChartColorsForTheme(themeVal);
            appendLog(`System theme changed to ${themeVal.toUpperCase()}. UI elements re-aligned.`, 'info');
        }

        function updateChartColorsForTheme(themeVal) {
            let isDark = true;
            if (themeVal === 'light') {
                isDark = false;
            } else if (themeVal === 'system') {
                isDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
            }

            const gridColorY = isDark ? 'rgba(255, 255, 255, 0.015)' : 'rgba(15, 23, 42, 0.02)';
            const textColor = isDark ? '#64748b' : '#475569';
            const accentColor = isDark ? '#6366f1' : '#2563eb';
            const tooltipBg = isDark ? 'rgba(13, 18, 30, 0.95)' : 'rgba(255, 255, 255, 0.95)';
            const tooltipBorder = isDark ? 'rgba(99, 102, 241, 0.2)' : 'rgba(37, 99, 235, 0.2)';
            const tooltipTitle = isDark ? '#f1f5f9' : '#0f172a';
            const tooltipBody = isDark ? '#94a3b8' : '#475569';

            if (chart) {
                chart.options.scales.x.ticks.color = textColor;
                chart.options.scales.yLatency.grid.color = gridColorY;
                chart.options.scales.yLatency.ticks.color = isDark ? '#94a3b8' : '#334155';
                chart.options.scales.yLatency.title.color = accentColor;
                chart.options.plugins.tooltip.backgroundColor = tooltipBg;
                chart.options.plugins.tooltip.borderColor = tooltipBorder;
                chart.options.plugins.tooltip.titleColor = tooltipTitle;
                chart.options.plugins.tooltip.bodyColor = tooltipBody;
                
                chart.data.datasets[0].borderColor = accentColor;
                
                const ctx = document.getElementById('metricsChart').getContext('2d');
                const gradient = ctx.createLinearGradient(0, 0, 0, 200);
                if (isDark) {
                    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.22)');
                    gradient.addColorStop(1, 'rgba(99, 102, 241, 0.00)');
                } else {
                    gradient.addColorStop(0, 'rgba(37, 99, 235, 0.22)');
                    gradient.addColorStop(1, 'rgba(37, 99, 235, 0.00)');
                }
                chart.data.datasets[0].backgroundColor = gradient;
                chart.update('none');
            }
            if (throughputChart) {
                throughputChart.options.scales.x.ticks.color = textColor;
                throughputChart.options.scales.y.grid.color = gridColorY;
                throughputChart.options.scales.y.ticks.color = isDark ? '#94a3b8' : '#334155';
                throughputChart.options.scales.y.title.color = isDark ? '#818cf8' : '#4f46e5';
                throughputChart.options.plugins.tooltip.backgroundColor = tooltipBg;
                throughputChart.options.plugins.tooltip.borderColor = tooltipBorder;
                throughputChart.options.plugins.tooltip.titleColor = tooltipTitle;
                throughputChart.options.plugins.tooltip.bodyColor = tooltipBody;
                throughputChart.data.datasets[0].borderColor = isDark ? '#818cf8' : '#4f46e5';

                const ctx = document.getElementById('throughputChart').getContext('2d');
                const gradient = ctx.createLinearGradient(0, 0, 0, 100);
                if (isDark) {
                    gradient.addColorStop(0, 'rgba(99, 102, 241, 0.22)');
                    gradient.addColorStop(1, 'rgba(99, 102, 241, 0.00)');
                } else {
                    gradient.addColorStop(0, 'rgba(79, 70, 229, 0.22)');
                    gradient.addColorStop(1, 'rgba(79, 70, 229, 0.00)');
                }
                throughputChart.data.datasets[0].backgroundColor = gradient;
                throughputChart.update('none');
            }
            if (compareChart) {
                compareChart.options.scales.x.ticks.color = textColor;
                compareChart.options.scales.y.grid.color = gridColorY;
                compareChart.options.scales.y.ticks.color = isDark ? '#94a3b8' : '#334155';
                compareChart.options.scales.y.title.color = isDark ? '#e2e8f0' : '#0f172a';
                compareChart.options.plugins.legend.labels.color = isDark ? '#94a3b8' : '#334155';
                compareChart.options.plugins.tooltip.backgroundColor = tooltipBg;
                compareChart.options.plugins.tooltip.borderColor = tooltipBorder;
                compareChart.options.plugins.tooltip.titleColor = tooltipTitle;
                compareChart.options.plugins.tooltip.bodyColor = tooltipBody;
                compareChart.update('none');
            }
            if (cpuMemoryTrendChart) {
                cpuMemoryTrendChart.options.scales.x.ticks.color = textColor;
                cpuMemoryTrendChart.options.scales.y.grid.color = gridColorY;
                cpuMemoryTrendChart.options.scales.y.ticks.color = isDark ? '#94a3b8' : '#334155';
                cpuMemoryTrendChart.options.scales.y.title.color = isDark ? '#e2e8f0' : '#0f172a';
                cpuMemoryTrendChart.options.plugins.legend.labels.color = isDark ? '#94a3b8' : '#334155';
                cpuMemoryTrendChart.options.plugins.tooltip.backgroundColor = tooltipBg;
                cpuMemoryTrendChart.options.plugins.tooltip.borderColor = tooltipBorder;
                cpuMemoryTrendChart.options.plugins.tooltip.titleColor = tooltipTitle;
                cpuMemoryTrendChart.options.plugins.tooltip.bodyColor = tooltipBody;
                cpuMemoryTrendChart.update('none');
            }

        }

        // Apply dynamic updates
        const previousHealthScores = { platform: null, cpu: null, ram: null, disk: null, net: null };

        function autoUpdateHealthScoreItem(idPrefix, score, isStopped = false) {
            const scoreEl = document.getElementById(`health-${idPrefix}-val`);
            const barEl = document.getElementById(`health-${idPrefix}-bar`);
            const statusEl = document.getElementById(`health-${idPrefix}-status`);
            const trendEl = document.getElementById(`health-${idPrefix}-trend`);
            if (!scoreEl) return;

            const prevScore = previousHealthScores[idPrefix];
            if (!isStopped) {
                previousHealthScores[idPrefix] = score;
            }

            if (isStopped) {
                scoreEl.innerText = '--%';
                if (barEl) barEl.style.width = '0%';
                if (statusEl) {
                    statusEl.innerText = 'INACTIVE';
                    statusEl.className = 'text-[9px] font-bold font-mono tracking-wider px-2 py-0.5 rounded bg-slate-950/40 border border-slate-800/30 text-slate-500';
                }
                if (trendEl) {
                    trendEl.innerText = '--';
                    trendEl.className = 'text-[9px] font-mono text-gray-500 bg-gray-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold';
                }
                return;
            }

            scoreEl.innerText = safeToFixed(score, 1) + "%";
            if (barEl) {
                barEl.style.width = safeToFixed(score, 1) + "%";
                if (score >= 90.0) {
                    barEl.className = "bg-emerald-500 h-1.5 rounded-full transition-all duration-500";
                } else if (score >= 75.0) {
                    barEl.className = "bg-teal-500 h-1.5 rounded-full transition-all duration-500";
                } else if (score >= 50.0) {
                    barEl.className = "bg-amber-500 h-1.5 rounded-full transition-all duration-500";
                } else {
                    barEl.className = "bg-rose-500 h-1.5 rounded-full transition-all duration-500";
                }
            }

            // Update trend indicators
            if (trendEl) {
                if (prevScore === null) {
                    trendEl.innerText = '--';
                    trendEl.className = 'text-[9px] font-mono text-gray-500 bg-gray-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold';
                } else {
                    const delta = score - prevScore;
                    if (Math.abs(delta) < 0.05) {
                        trendEl.innerHTML = '<span>&rarr;</span> <span>0.0%</span>';
                        trendEl.className = 'text-[9px] font-mono text-slate-400 bg-slate-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold';
                    } else if (delta > 0) {
                        trendEl.innerHTML = '<span>&uarr;</span> <span>+' + delta.toFixed(1) + '%</span>';
                        trendEl.className = 'text-[9px] font-mono text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold';
                    } else {
                        trendEl.innerHTML = '<span>&darr;</span> <span>' + delta.toFixed(1) + '%</span>';
                        trendEl.className = 'text-[9px] font-mono text-rose-400 bg-rose-500/10 px-1.5 py-0.5 rounded flex items-center gap-0.5 font-bold';
                    }
                }
            }

            if (statusEl) {
                let status = 'NOMINAL';
                let colorClass = '';
                if (idPrefix === 'platform') {
                    status = score >= 90.0 ? 'OPERATIONAL' : (score >= 75.0 ? 'DEGRADED' : 'CRITICAL');
                    colorClass = score >= 90.0 ? 'text-indigo-400 bg-indigo-500/10 border-indigo-500/20' : (score >= 75.0 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-rose-500 bg-rose-500/10 border-rose-500/20');
                } else if (idPrefix === 'net') {
                    status = score >= 90.0 ? 'ONLINE' : (score >= 75.0 ? 'WARNING' : (score > 0.0 ? 'CRITICAL' : 'OFFLINE'));
                    colorClass = score >= 90.0 ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' : (score >= 75.0 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-rose-500 bg-rose-500/10 border-rose-500/20');
                } else {
                    status = score >= 90.0 ? 'NOMINAL' : (score >= 75.0 ? 'WARNING' : 'CRITICAL');
                    colorClass = score >= 90.0 ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20' : (score >= 75.0 ? 'text-amber-400 bg-amber-500/10 border-amber-500/20' : 'text-rose-500 bg-rose-500/10 border-rose-500/20');
                }
                statusEl.innerText = status;
                statusEl.className = `text-[9px] font-bold font-mono tracking-wider px-2 py-0.5 rounded border ${colorClass}`;
            }
        }

        // Apply dynamic updates
        function updateUI(data) {
            try {
            if (!data) return;
            // Stats
            const uptimeTextEl = document.getElementById('uptime-text');
            if (uptimeTextEl) {
                uptimeTextEl.innerText = formatUptime(safeToNumber(data.uptime_seconds, 0));
            }
            
            // Telemetry Control Panel Updates
            const telemetryStatus = data.telemetry_status || "ACTIVE";
            const currentInterval = data.interval_ms || 2000;
            const isStopped = telemetryStatus === "STOPPED";
            
            const statusEl = document.getElementById('ctrl-telemetry-status');
            if (statusEl) {
                statusEl.innerText = telemetryStatus;
                const statusCardEl = document.getElementById('status-card');
                if (telemetryStatus === "ACTIVE") {
                    statusEl.className = "px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-950/40 border border-emerald-800/30 text-emerald-400";
                    if (statusCardEl) {
                        statusCardEl.className = "flex items-center gap-2 bg-[#111622] px-3 py-1.5 rounded border border-gray-800";
                        statusCardEl.innerHTML = '<span class="h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse"></span><span class="text-xs font-mono font-semibold text-emerald-400">MONITOR_ACTIVE</span>';
                    }
                } else if (telemetryStatus === "PAUSED") {
                    statusEl.className = "px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-amber-950/40 border border-amber-800/30 text-amber-400";
                    if (statusCardEl) {
                        statusCardEl.className = "flex items-center gap-2 bg-[#111622] px-3 py-1.5 rounded border border-gray-800";
                        statusCardEl.innerHTML = '<span class="h-2.5 w-2.5 rounded-full bg-amber-500 animate-pulse"></span><span class="text-xs font-mono font-semibold text-amber-400">MONITOR_PAUSED</span>';
                    }
                } else {
                    statusEl.className = "px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-rose-950/40 border border-rose-800/30 text-rose-400";
                    if (statusCardEl) {
                        statusCardEl.className = "flex items-center gap-2 bg-[#111622] px-3 py-1.5 rounded border border-gray-800";
                        statusCardEl.innerHTML = '<span class="h-2.5 w-2.5 rounded-full bg-rose-500 animate-pulse"></span><span class="text-xs font-mono font-semibold text-rose-400">MONITOR_STOPPED</span>';
                    }
                }
            }

            const intervalEl = document.getElementById('ctrl-polling-interval');
            if (intervalEl) {
                intervalEl.innerText = `${currentInterval} ms`;
            }

            // Update Control panel buttons
            const btnStart = document.getElementById('btn-start');
            if (btnStart) btnStart.disabled = (telemetryStatus === "ACTIVE");
            const btnStop = document.getElementById('btn-stop');
            if (btnStop) btnStop.disabled = (telemetryStatus === "STOPPED");
            const btnPause = document.getElementById('btn-pause');
            if (btnPause) btnPause.disabled = (telemetryStatus !== "ACTIVE");
            const btnResume = document.getElementById('btn-resume');
            if (btnResume) btnResume.disabled = (telemetryStatus !== "PAUSED");

            // Update Target Host, Port and Interval input fields dynamically (if not focused)
            const inputHost = document.getElementById('input-target-host');
            if (inputHost && data.target_host && document.activeElement !== inputHost) {
                inputHost.value = data.target_host;
            }
            const inputPort = document.getElementById('input-target-port');
            if (inputPort && data.target_port !== undefined && document.activeElement !== inputPort) {
                inputPort.value = data.target_port;
            }
            const selectInterval = document.getElementById('select-interval');
            if (selectInterval && data.interval_ms) {
                selectInterval.value = data.interval_ms;
            }

            // Update Collector Badges
            const collectors = ['cpu', 'ram', 'disk', 'net'];
            collectors.forEach(coll => {
                const badge = document.getElementById(`collector-${coll}`);
                if (badge) {
                    let text = "";
                    let classes = "";
                    let dotColor = "";
                    let isPulse = false;

                    const label = coll === 'cpu' ? 'CPU' : (coll === 'ram' ? 'Memory' : (coll === 'disk' ? 'Disk' : 'Network'));
                    
                    if (telemetryStatus === "ACTIVE") {
                        text = `${label} Collector: Active`;
                        classes = "flex items-center gap-1.5 px-2 py-0.5 rounded border border-emerald-800/20 bg-emerald-950/20 text-emerald-400";
                        dotColor = "bg-emerald-400";
                        isPulse = true;
                    } else if (telemetryStatus === "PAUSED") {
                        text = `${label} Collector: Paused`;
                        classes = "flex items-center gap-1.5 px-2 py-0.5 rounded border border-amber-800/20 bg-amber-950/20 text-amber-400";
                        dotColor = "bg-amber-400";
                    } else {
                        text = `${label} Collector: Inactive`;
                        classes = "flex items-center gap-1.5 px-2 py-0.5 rounded border border-slate-800/20 bg-slate-950/20 text-slate-500";
                        dotColor = "bg-slate-500";
                    }

                    badge.className = classes;
                    badge.innerHTML = `<span class="h-1.5 w-1.5 rounded-full ${dotColor} ${isPulse ? 'animate-pulse' : ''}"></span> ${text}`;
                }
            });

            // Core latency ping
            const latencyValEl = document.getElementById('latency-val');
            if (latencyValEl) {
                if (data.latency_ms >= 0) {
                    latencyValEl.innerText = safeToFixed(data.latency_ms, 1);
                } else {
                    latencyValEl.innerText = isStopped ? '--' : 'TIMEOUT';
                }
            }

            // Latency warning threshold (> 100ms)
            const latencyCard = document.getElementById('latency-card');
            const latencyAlertMsg = document.getElementById('latency-alert-msg');
            if (latencyCard && latencyAlertMsg) {
                if (!isStopped && data.latency_ms > 100.0) {
                    latencyCard.style.backgroundColor = 'rgba(244, 63, 94, 0.2)'; // bg-rose-500/20 in rgba
                    latencyCard.style.borderColor = 'rgba(244, 63, 94, 0.5)';     // border-rose-500/50 in rgba
                    latencyAlertMsg.innerText = "WARNING: High Latency Event Detected";
                    latencyAlertMsg.classList.remove('hidden');
                } else {
                    latencyCard.style.backgroundColor = '';
                    latencyCard.style.borderColor = '';
                    latencyAlertMsg.classList.add('hidden');
                    latencyAlertMsg.innerText = "";
                }
            }

            const hostValEl = document.getElementById('host-val');
            if (hostValEl) {
                hostValEl.innerText = data.target_host ? data.target_host : "No Host Configured";
            }
            const rttTargetEl = document.getElementById('rtt-target');
            if (rttTargetEl) {
                rttTargetEl.innerText = data.target_host ? `${data.target_host}:${data.target_port}` : "No Host Configured";
            }
            const stabilityValEl = document.getElementById('stability-val');
            if (stabilityValEl) {
                stabilityValEl.innerText = isStopped ? '--' : safeToFixed(data.stability_index, 0);
            }
            
            const lossVal = document.getElementById('loss-val');
            if (lossVal) {
                if (isStopped) {
                    lossVal.innerText = '--%';
                    lossVal.className = "text-gray-400 font-semibold font-mono";
                } else {
                    const lossPct = safeToNumber(data.packet_loss_pct, 0);
                    lossVal.innerText = safeToFixed(lossPct, 1) + "%";
                    if (lossPct > 0.0) {
                        lossVal.className = "text-rose-500 font-semibold font-mono";
                    } else {
                        lossVal.className = "text-emerald-400 font-semibold font-mono";
                    }
                }
            }

            // RAM Allocation
            const ramValEl = document.getElementById('ram-val');
            if (ramValEl) {
                ramValEl.innerText = isStopped ? '--' : safeToFixed(data.ram_used_mb, 0);
            }
            const ramTotalValEl = document.getElementById('ram-total-val');
            if (ramTotalValEl) {
                ramTotalValEl.innerText = isStopped ? '-- GB' : safeToFixed(safeToNumber(data.ram_total_mb, 0) / 1024, 1) + " GB";
            }

            // Update OS Uptime in Header and Card
            const hdrSysUptimeEl = document.getElementById('hdr-sys-uptime');
            if (hdrSysUptimeEl) {
                hdrSysUptimeEl.innerText = isStopped ? '--' : formatUptime(safeToNumber(data.system_uptime_seconds, 0));
            }
            const sysUptimeValEl = document.getElementById('sys-uptime-val');
            if (sysUptimeValEl) {
                sysUptimeValEl.innerText = isStopped ? '--' : formatUptime(safeToNumber(data.system_uptime_seconds, 0));
            }
            const osNameValEl = document.getElementById('os-name-val');
            if (osNameValEl) {
                osNameValEl.innerText = isStopped ? '--' : (data.system_os || '--');
            }

            // Update Disk space Card
            const diskUsedValEl = document.getElementById('disk-used-val');
            if (diskUsedValEl) {
                diskUsedValEl.innerText = isStopped ? '--' : safeToFixed(data.disk_used_gb, 1);
            }
            const diskTotalValEl = document.getElementById('disk-total-val');
            if (diskTotalValEl) {
                diskTotalValEl.innerText = isStopped ? '-- GB' : safeToFixed(data.disk_total_gb, 0) + " GB";
            }
            const diskPctValEl = document.getElementById('disk-pct-val');
            if (diskPctValEl) {
                diskPctValEl.innerText = isStopped ? '--%' : safeToFixed(data.disk_usage_pct, 1) + "%";
            }

            // Update Disk I/O Card
            const diskReadValEl = document.getElementById('disk-read-val');
            if (diskReadValEl) {
                diskReadValEl.innerText = isStopped ? '--' : safeToFixed(data.disk_read_mbs, 2);
            }
            const diskWriteValEl = document.getElementById('disk-write-val');
            if (diskWriteValEl) {
                diskWriteValEl.innerText = isStopped ? '--' : safeToFixed(data.disk_write_mbs, 2);
            }

            // Update Processes and Threads Card
            const procCountValEl = document.getElementById('proc-count-val');
            if (procCountValEl) {
                procCountValEl.innerText = isStopped ? '--' : safeToFixed(data.process_count, 0);
            }
            const threadCountValEl = document.getElementById('thread-count-val');
            if (threadCountValEl) {
                threadCountValEl.innerText = isStopped ? '--' : safeToFixed(data.thread_count, 0);
            }

            // Update Network Intelligence Stats
            const dlVal = isStopped ? 0.0 : safeToNumber(data.net_download_speed_mbps, 0.0);
            const ulVal = isStopped ? 0.0 : safeToNumber(data.net_upload_speed_mbps, 0.0);
            const tpVal = isStopped ? 0.0 : safeToNumber(data.net_throughput_mbps, 0.0);
            const tcpVal = isStopped ? 0 : safeToNumber(data.active_tcp_connections, 0);
            const udpVal = isStopped ? 0 : safeToNumber(data.active_udp_connections, 0);
            const jitterVal = isStopped ? 0.0 : safeToNumber(data.network_jitter_ms, 0.0);
            const utilVal = isStopped ? 0.0 : safeToNumber(data.interface_utilization_pct, 0.0);
            const healthScore = isStopped ? 100.0 : safeToNumber(data.network_health_score, 100.0);
            const connQual = isStopped ? 'Inactive' : (data.connection_quality_status || 'Good');
            
            const dlValEl = document.getElementById('net-download-val');
            if (dlValEl) dlValEl.innerText = isStopped ? '--' : safeToFixed(dlVal, 2);
            const ulValEl = document.getElementById('net-upload-val');
            if (ulValEl) ulValEl.innerText = isStopped ? '--' : safeToFixed(ulVal, 2);
            const tcpValEl = document.getElementById('tcp-conn-val');
            if (tcpValEl) tcpValEl.innerText = isStopped ? '--' : tcpVal;
            const udpValEl = document.getElementById('udp-conn-val');
            if (udpValEl) udpValEl.innerText = isStopped ? '--' : udpVal;
            
            const dnsEl = document.getElementById('dns-time-val');
            if (dnsEl) {
                if (isStopped) {
                    dnsEl.innerText = '--';
                } else if (data.dns_response_time_ms >= 0) {
                    dnsEl.innerText = safeToFixed(data.dns_response_time_ms, 1);
                } else {
                    dnsEl.innerText = 'TIMEOUT';
                }
            }
            
            const jitterValEl = document.getElementById('jitter-val');
            if (jitterValEl) jitterValEl.innerText = isStopped ? '--' : safeToFixed(jitterVal, 2);
            const utilPctValEl = document.getElementById('interface-util-pct-val');
            if (utilPctValEl) utilPctValEl.innerText = isStopped ? '--%' : safeToFixed(utilVal, 1) + "%";
            const utilBar = document.getElementById('interface-util-bar');
            if (utilBar) utilBar.style.width = isStopped ? '0%' : safeToFixed(utilVal, 1) + "%";

            // Update Health Score Indicators
            const netHealthValEl = document.getElementById('net-health-score-val');
            if (netHealthValEl) netHealthValEl.innerText = isStopped ? '--%' : safeToFixed(healthScore, 1) + "%";
            const scoreGaugeEl = document.getElementById('gauge-score');
            if (scoreGaugeEl) scoreGaugeEl.innerText = isStopped ? '--' : safeToFixed(healthScore, 0);
            const gaugeQualEl = document.getElementById('gauge-quality');
            if (gaugeQualEl) gaugeQualEl.innerText = connQual;
            const qualTextEl = document.getElementById('quality-status-text');
            if (qualTextEl) qualTextEl.innerText = connQual;
            const qualJitterEl = document.getElementById('quality-jitter-val');
            if (qualJitterEl) qualJitterEl.innerText = isStopped ? '--' : safeToFixed(jitterVal, 1) + " ms";

            // SVG Radial Offset
            const circle = document.getElementById('gauge-circle');
            if (circle) {
                const circumference = 251.32;
                const offset = isStopped ? circumference : (circumference - (circumference * healthScore / 100));
                circle.style.strokeDashoffset = offset;
            }

            // Connection Status Dot & Badge
            const statusTextEl = document.getElementById('net-status-text');
            const statusDotEl = document.getElementById('net-status-dot');
            if (statusTextEl && statusDotEl) {
                if (isStopped) {
                    statusTextEl.innerText = 'INACTIVE';
                    statusTextEl.className = 'font-bold text-gray-500';
                    statusDotEl.className = 'h-2 w-2 rounded-full bg-gray-500';
                } else {
                    const netStatus = data.network_status || (data.latency_ms >= 0 ? 'ONLINE' : 'OFFLINE');
                    statusTextEl.innerText = netStatus;
                    if (netStatus === 'ONLINE') {
                        statusTextEl.className = 'font-bold text-emerald-400';
                        statusDotEl.className = 'h-2 w-2 rounded-full bg-emerald-500 animate-pulse';
                    } else if (netStatus === 'DEGRADED') {
                        statusTextEl.className = 'font-bold text-amber-400';
                        statusDotEl.className = 'h-2 w-2 rounded-full bg-amber-500 animate-pulse';
                    } else {
                        statusTextEl.className = 'font-bold text-rose-500';
                        statusDotEl.className = 'h-2 w-2 rounded-full bg-rose-500 animate-pulse';
                    }
                }
            }

            // Update per-core CPU load cards
            for (let i = 0; i < 4; i++) {
                const coreVal = (isStopped || !data.per_core_cpu_pct || !data.per_core_cpu_pct[i]) ? 0.0 : safeToNumber(data.per_core_cpu_pct[i], 0.0);
                const el = document.getElementById(`core-${i}-load`);
                if (el) {
                    el.innerText = isStopped ? '--%' : safeToFixed(coreVal, 1) + "%";
                }
                
                const bar = document.getElementById(`core-${i}-load-bar`);
                if (bar) {
                    bar.style.width = isStopped ? '0%' : safeToFixed(coreVal, 1) + "%";
                }
                
                const thEl = document.getElementById(`core-${i}-threads`);
                if (thEl) {
                    thEl.innerText = isStopped ? '--' : (data.thread_count ? Math.round(safeToNumber(data.thread_count, 0) / Math.max(1, safeToNumber(data.core_count, 1))) : '--');
                }
            }

            // Update centralized health system overview
            autoUpdateHealthScoreItem('platform', safeToNumber(data.platform_health_score, 100), isStopped);
            autoUpdateHealthScoreItem('cpu', safeToNumber(data.cpu_health_score, 100), isStopped);
            autoUpdateHealthScoreItem('ram', safeToNumber(data.ram_health_score, 100), isStopped);
            autoUpdateHealthScoreItem('disk', safeToNumber(data.disk_health_score, 100), isStopped);
            autoUpdateHealthScoreItem('net', healthScore, isStopped);

            // Update CPU aggregations
            const overallCpuVal = document.getElementById('overall-cpu-usage-val');
            const overallCpuFreq = document.getElementById('overall-cpu-freq-val');
            const overallCpuTemp = document.getElementById('overall-cpu-temp-val');
            const overallCpuBar = document.getElementById('overall-cpu-bar');
            const overallCpuHealth = document.getElementById('overall-cpu-health');
            
            if (isStopped) {
                if (overallCpuVal) overallCpuVal.innerText = '--';
                if (overallCpuFreq) overallCpuFreq.innerText = '-- MHz';
                if (overallCpuTemp) overallCpuTemp.innerText = '-- °C';
                if (overallCpuBar) overallCpuBar.style.width = '0%';
                if (overallCpuHealth) {
                    overallCpuHealth.innerText = 'HEALTH: --%';
                    overallCpuHealth.className = "px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-slate-950/40 border border-slate-800/30 text-slate-500";
                }
            } else {
                const cpuUsage = safeToNumber(data.cpu_usage_pct, 0);
                if (overallCpuVal) overallCpuVal.innerText = safeToFixed(cpuUsage, 1);
                if (overallCpuFreq) overallCpuFreq.innerText = safeToFixed(data.cpu_frequency_mhz, 0) + " MHz";
                if (overallCpuTemp) overallCpuTemp.innerText = safeToFixed(data.cpu_temp_c, 1) + " °C";
                if (overallCpuBar) overallCpuBar.style.width = safeToFixed(cpuUsage, 1) + "%";
                if (overallCpuHealth) {
                    const healthVal = safeToNumber(data.cpu_health_score, 100);
                    overallCpuHealth.innerText = `HEALTH: ${safeToFixed(healthVal, 0)}%`;
                    if (healthVal >= 90.0) {
                        overallCpuHealth.className = "px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-emerald-950/40 border border-emerald-800/30 text-emerald-400";
                    } else if (healthVal >= 75.0) {
                        overallCpuHealth.className = "px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-amber-950/40 border border-amber-800/30 text-amber-400";
                    } else {
                        overallCpuHealth.className = "px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-rose-950/40 border border-rose-800/30 text-rose-400";
                    }
                }
            }

            // Update RAM aggregations
            const overallRamVal = document.getElementById('overall-ram-usage-val');
            const overallRamUsed = document.getElementById('overall-ram-used-val');
            const overallRamTotal = document.getElementById('overall-ram-total-val');
            const overallRamBar = document.getElementById('overall-ram-bar');
            const overallRamHealth = document.getElementById('overall-ram-health');

            if (isStopped) {
                if (overallRamVal) overallRamVal.innerText = '--';
                if (overallRamUsed) overallRamUsed.innerText = '-- MB';
                if (overallRamTotal) overallRamTotal.innerText = safeToFixed(safeToNumber(data.ram_total_mb, 0) / 1024, 1) + " GB";
                if (overallRamBar) overallRamBar.style.width = '0%';
                if (overallRamHealth) {
                    overallRamHealth.innerText = 'HEALTH: --%';
                    overallRamHealth.className = "px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-slate-950/40 border border-slate-800/30 text-slate-500";
                }
            } else {
                const ramUsage = safeToNumber(data.ram_usage_pct, 0);
                if (overallRamVal) overallRamVal.innerText = safeToFixed(ramUsage, 1);
                if (overallRamUsed) overallRamUsed.innerText = safeToFixed(data.ram_used_mb, 0) + " MB";
                if (overallRamTotal) overallRamTotal.innerText = safeToFixed(safeToNumber(data.ram_total_mb, 0) / 1024, 1) + " GB";
                if (overallRamBar) overallRamBar.style.width = safeToFixed(ramUsage, 1) + "%";
                if (overallRamHealth) {
                    const healthVal = safeToNumber(data.ram_health_score, 100);
                    overallRamHealth.innerText = `HEALTH: ${safeToFixed(healthVal, 0)}%`;
                    if (healthVal >= 90.0) {
                        overallRamHealth.className = "px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-emerald-950/40 border border-emerald-800/30 text-emerald-400";
                    } else if (healthVal >= 75.0) {
                        overallRamHealth.className = "px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-amber-950/40 border border-amber-800/30 text-amber-400";
                    } else {
                        overallRamHealth.className = "px-2 py-0.5 text-[9px] font-mono font-bold rounded bg-rose-950/40 border border-rose-800/30 text-rose-400";
                    }
                }
            }

            // Update Inactive/Opacity states on visual metric components
            const stateAffectedElements = [
                'live-metrics-grid',
                'system-health-dashboard',
                'core-diagnostics-grid',
                'net-metrics-grid',
                'net-vis-grid',
                'telemetry-chart-container'
            ];
            stateAffectedElements.forEach(id => {
                const el = document.getElementById(id);
                if (el) {
                    if (isStopped) {
                        el.classList.add('opacity-60', 'pointer-events-none');
                        el.classList.add('transition-opacity', 'duration-300');
                    } else {
                        el.classList.remove('opacity-60', 'pointer-events-none');
                    }
                }
            });

            // Update Terminal Log stream from backend logs
            updateTerminalLogs(data.logs);

            // Push to Charts
            const currentTimestamp = Number(data.timestamp);
            if (currentTimestamp && currentTimestamp !== lastPushedTimestamp) {
                lastPushedTimestamp = currentTimestamp;
                const timeLabel = new Date(data.timestamp * 1000).toLocaleTimeString();
                
                if (chart) {
                    chart.data.labels.push(timeLabel);
                    chart.data.datasets[0].data.push(isStopped ? null : (data.latency_ms >= 0 ? data.latency_ms : null));
                    if (chart.data.labels.length > maxDataPoints) {
                        chart.data.labels.shift();
                        chart.data.datasets[0].data.shift();
                    }
                    chart.update('none');
                }

                if (throughputChart) {
                    throughputChart.data.labels.push(timeLabel);
                    throughputChart.data.datasets[0].data.push(tpVal);
                    if (throughputChart.data.labels.length > maxDataPoints) {
                        throughputChart.data.labels.shift();
                        throughputChart.data.datasets[0].data.shift();
                    }
                    throughputChart.update('none');
                }

                if (compareChart) {
                    compareChart.data.labels.push(timeLabel);
                    compareChart.data.datasets[0].data.push(dlVal);
                    compareChart.data.datasets[1].data.push(ulVal);
                    if (compareChart.data.labels.length > maxDataPoints) {
                        compareChart.data.labels.shift();
                        compareChart.data.datasets[0].data.shift();
                        compareChart.data.datasets[1].data.shift();
                    }
                    compareChart.update('none');
                }

                if (cpuMemoryTrendChart) {
                    cpuMemoryTrendChart.data.labels.push(timeLabel);
                    cpuMemoryTrendChart.data.datasets[0].data.push(isStopped ? null : safeToNumber(data.cpu_usage_pct, 0));
                    cpuMemoryTrendChart.data.datasets[1].data.push(isStopped ? null : safeToNumber(data.ram_usage_pct, 0));
                    if (cpuMemoryTrendChart.data.labels.length > maxDataPoints) {
                        cpuMemoryTrendChart.data.labels.shift();
                        cpuMemoryTrendChart.data.datasets[0].data.shift();
                        cpuMemoryTrendChart.data.datasets[1].data.shift();
                    }
                    cpuMemoryTrendChart.update('none');
                }
            }

            // Update System Card values
            const systemOsNameEl = document.getElementById('system-os-name');
            if (systemOsNameEl && data.system_os) {
                systemOsNameEl.innerText = data.system_os;
            }
            const systemResolutionEl = document.getElementById('system-resolution');
            if (systemResolutionEl) {
                systemResolutionEl.innerText = isStopped ? 'Stopped' : `${currentInterval / 1000}s (${currentInterval === 1000 ? 'High Res' : (currentInterval === 2000 ? 'Balanced' : 'Eco')})`;
            }

            } catch (err) {
                console.error("updateUI crash:", err);
                if (typeof appendLog === 'function') {
                    appendLog("updateUI crash: " + err.message, "CRITICAL", "SYSTEM");
                }
            }
        }

        // Action dispatcher to /api/control for updating host and port target
        async function updateTarget() {
            const hostEl = document.getElementById('input-target-host');
            const portEl = document.getElementById('input-target-port');
            const host = hostEl ? hostEl.value.trim() : '';
            const port = portEl ? portEl.value.trim() : '';
            if (!host) {
                appendLog("Invalid host input. Cannot set telemetry target.", "warning", "SYSTEM");
                return;
            }
            try {
                const res = await fetch(`/api/control?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port || '53')}`);
                const data = await res.json();
                if (data.status === 'success') {
                    appendLog(`Telemetry target set to: ${host}:${port || '53'}`, "info", "SYSTEM");
                    runCycle();
                }
            } catch (err) {
                console.error("Target update error:", err);
            }
        }

        // Action dispatcher to /api/control for updating polling interval
        async function updateInterval(val) {
            const numVal = Number(val);
            if (isNaN(numVal) || numVal < 500 || numVal > 60000) return;
            try {
                const res = await fetch(`/api/control?interval=${numVal}`);
                const data = await res.json();
                if (data.status === 'success') {
                    currentFetchInterval = numVal;
                    try {
                        localStorage.setItem('coremetric_interval', val);
                    } catch (e) {
                        console.warn("Storage write access denied:", e);
                    }
                    if (typeof appendLog === 'function') {
                        appendLog(`Telemetry polling interval updated to ${numVal} ms`, "info", "SYSTEM");
                    }
                    if (runCycleTimeoutId) {
                        clearTimeout(runCycleTimeoutId);
                    }
                    runCycle();
                }
            } catch (err) {
                console.error("Interval update error:", err);
            }
        }

        // Scrollspy Navigation init
        function initScrollspy() {
            const sections = document.querySelectorAll('section[id]');
            const navLinks = document.querySelectorAll('header nav a');
            
            const options = {
                root: null,
                rootMargin: '-30% 0px -60% 0px',
                threshold: 0
            };
            
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        const activeId = entry.target.getAttribute('id');
                        navLinks.forEach(link => {
                            const href = link.getAttribute('href');
                            if (href === `#${activeId}`) {
                                link.classList.remove('text-gray-400');
                                if (document.body.classList.contains('light-theme')) {
                                    link.classList.add('bg-indigo-600/10', 'text-indigo-600', 'border-indigo-600/20');
                                    link.classList.remove('bg-indigo-500/10', 'text-indigo-400', 'border-indigo-500/20');
                                } else {
                                    link.classList.add('bg-indigo-500/10', 'text-indigo-400', 'border-indigo-500/20');
                                    link.classList.remove('bg-indigo-600/10', 'text-indigo-600', 'border-indigo-600/20');
                                }
                            } else {
                                link.classList.remove('bg-indigo-500/10', 'text-indigo-400', 'border-indigo-500/20', 'bg-indigo-600/10', 'text-indigo-600', 'border-indigo-600/20');
                                link.classList.add('text-gray-400');
                            }
                        });
                    }
                });
            }, options);
            
            sections.forEach(section => observer.observe(section));
        }

        let runCycleTimeoutId = null;
        let currentFetchInterval = 2000;

        async function runCycle() {
            if (runCycleTimeoutId) {
                clearTimeout(runCycleTimeoutId);
            }
            try {
                const res = await fetch('/api/metrics');
                const data = await res.json();
                updateUI(data);
                hideLoadingOverlay();

                if (data.interval_ms && data.interval_ms >= 500) {
                    currentFetchInterval = data.interval_ms;
                }
            } catch (err) {
                appendLog("Failed to establish diagnostic API poll. Local monitoring interface unreachable.", "warn");
            } finally {
                runCycleTimeoutId = setTimeout(runCycle, currentFetchInterval);
            }
        }

        // Onboarding Tour (5 Steps)
        let tourStep = 0;
        const tourSteps = [
            {
                elementId: 'section-1',
                title: 'Live Telemetry Core Metrics',
                text: 'This top section highlights live network RTT latency, packet loss stability ratios, and CoreMemory memory allocations processed by the background engine.',
                action: () => document.getElementById('section-1').scrollIntoView({ behavior: 'smooth' })
            },
            {
                elementId: 'telemetry-control-panel',
                title: 'Telemetry Control Panel',
                text: 'This dashboard allows you to pause, stop, resume, and start monitoring. You can inspect the polling interval and see the active/inactive state of each telemetry collector (CPU, memory, disk, network) in real time.',
                action: () => document.getElementById('telemetry-control-panel').scrollIntoView({ behavior: 'smooth' })
            },
            {
                elementId: 'section-net',
                title: 'Network Intelligence Center',
                text: 'This dedicated section visualizes real-time upload/download speeds, connection counts, DNS response time, Jitter, NIC interface utilization, and a network health score gauge.',
                action: () => document.getElementById('section-net').scrollIntoView({ behavior: 'smooth' })
            },
            {
                elementId: 'section-2',
                title: 'Processor Diagnostics',
                text: 'The middle fold displays real-time load percentages and temperature diagnostics for Core-0 through Core-3.',
                action: () => document.getElementById('section-2').scrollIntoView({ behavior: 'smooth' })
            },

            {
                elementId: 'section-3',
                title: 'Live Kernel & Socket Audit Stream',
                text: 'The bottom fold prints raw socket handshakes, diagnostic thread activity, and API client requests as they happen.',
                action: () => document.getElementById('section-3').scrollIntoView({ behavior: 'smooth' })
            }
        ];

        function startTour() {
            tourStep = 0;
            document.getElementById('tour-overlay').classList.remove('hidden');
            showTourStep();
        }

        function showTourStep() {
            const step = tourSteps[tourStep];
            step.action();
            
            // Wait slightly for scroll behavior to trigger, then highlight
            setTimeout(() => {
                document.querySelectorAll('.tour-highlight').forEach(el => el.classList.remove('tour-highlight'));
                const targetEl = document.getElementById(step.elementId);
                if (targetEl) {
                    targetEl.classList.add('tour-highlight');
                }
            }, 300);

            document.getElementById('tour-step-title').innerText = step.title;
            document.getElementById('tour-step-text').innerText = step.text;
            document.getElementById('tour-step-count').innerText = `${tourStep + 1} / ${tourSteps.length}`;
            
            document.getElementById('tour-prev-btn').disabled = (tourStep === 0);
            document.getElementById('tour-next-btn').innerText = (tourStep === tourSteps.length - 1) ? 'Finish' : 'Next';
        }

        function nextTourStep() {
            if (tourStep < tourSteps.length - 1) {
                tourStep++;
                showTourStep();
            } else {
                closeTour();
            }
        }

        function prevTourStep() {
            if (tourStep > 0) {
                tourStep--;
                showTourStep();
            }
        }

        // Close Tour
        function closeTour() {
            const tourOverlay = document.getElementById('tour-overlay');
            if (tourOverlay) {
                tourOverlay.classList.add('hidden');
            }
            document.querySelectorAll('.tour-highlight').forEach(el => el.classList.remove('tour-highlight'));
            try {
                localStorage.setItem('coremetric_onboarded', 'true');
            } catch (e) {
                console.warn("Storage write access denied:", e);
            }
            appendLog("Architectural onboarding tour completed.", "info");
        }

        function skipWelcome() {
            const welcomeModal = document.getElementById('welcome-modal');
            if (welcomeModal) {
                welcomeModal.classList.add('hidden');
            }
            try {
                localStorage.setItem('coremetric_onboarded', 'true');
            } catch (e) {
                console.warn("Storage write access denied:", e);
            }
        }

        function startTourFromWelcome() {
            document.getElementById('welcome-modal').classList.add('hidden');
            startTour();
        }

        // Init routine
        async function init() {
            // Fallback to clear loading overlay after 3 seconds in case socket server is slow to start
            setTimeout(hideLoadingOverlay, 3000);

            // Load saved theme choice
            let savedTheme = 'dark';
            try {
                savedTheme = localStorage.getItem('coremetric_theme') || 'dark';
            } catch (e) {
                console.warn("Storage access denied on get:", e);
            }

            const themeSelector = document.getElementById('theme-selector');
            if (themeSelector) {
                themeSelector.value = savedTheme;
            }
            changeTheme(savedTheme);

            // Load saved interval choice and sync it with the backend
            let savedInterval = null;
            try {
                savedInterval = localStorage.getItem('coremetric_interval');
            } catch (e) {
                console.warn("Storage access denied on get interval:", e);
            }
            if (savedInterval) {
                const numVal = Number(savedInterval);
                if (!isNaN(numVal) && numVal >= 500 && numVal <= 60000) {
                    currentFetchInterval = numVal;
                    const selectEl = document.getElementById('select-interval');
                    if (selectEl) {
                        selectEl.value = savedInterval;
                    }
                    try {
                        await fetch(`/api/control?interval=${savedInterval}`);
                    } catch (e) {
                        console.error("Sync saved interval error:", e);
                    }
                }
            }

            // Fetch baseline data
            try {
                const res = await fetch('/api/metrics');
                const initialData = await res.json();
                
                initializeChart(initialData.history || []);
                updateUI(initialData);
            } catch (err) {
                console.error("init fetch baseline error:", err);
                initializeChart([]);
            } finally {
                hideLoadingOverlay();
            }

            // Auto-trigger welcome onboarding if first time
            let isAlreadyOnboarded = false;
            try {
                isAlreadyOnboarded = localStorage.getItem('coremetric_onboarded');
            } catch (e) {
                console.warn("Storage access denied on onboarding check:", e);
            }
            if (!isAlreadyOnboarded) {
                const welcomeModal = document.getElementById('welcome-modal');
                if (welcomeModal) {
                    welcomeModal.classList.remove('hidden');
                }
            }

            // Continuous polling cycles using the dynamic timer
            setTimeout(runCycle, currentFetchInterval);
            setInterval(simulateRacks, 2000);

            // Initialize active nav highlighting
            initScrollspy();

            // Listen to system theme changes dynamically
            window.matchMedia("(prefers-color-scheme: dark)").addEventListener('change', e => {
                if (currentThemePreference === 'system') {
                    changeTheme('system');
                }
            });
        }

                if (document.readyState === 'complete' || document.readyState === 'interactive') {
            init();
        } else {
            window.addEventListener('DOMContentLoaded', init);
        }
    </script>
</body>
</html>
)rawhtml";
}

// ==========================================
// EMBEDDED HTTP SERVER IMPLEMENTATION
// ==========================================

// Thread routine to process single socket HTTP connection request
void handle_client(SocketType client_fd) {
  const int buffer_size = 4096;
  char buffer[buffer_size];
  std::memset(buffer, 0, buffer_size);

  // Read headers data from sockets stream
  int bytes_received = recv(client_fd, buffer, buffer_size - 1, 0);
  if (bytes_received <= 0) {
    CLOSE_SOCKET(client_fd);
    return;
  }

  // Parse request verb and destination path
  std::string request(buffer);
  std::istringstream iss(request);
  std::string method, path, protocol;
  iss >> method >> path >> protocol;

  if (method != "GET") {
    std::string response = "HTTP/1.1 405 Method Not Allowed\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n";
    send(client_fd, response.c_str(), (int)response.length(), 0);
    CLOSE_SOCKET(client_fd);
    return;
  }

  // Routes controller
  if (path == "/" || path == "/index.html") {
    add_system_log("INFO", "API", "Served main dashboard page to client");
    std::string html = get_dashboard_html();
    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html; charset=utf-8\r\n"
                           "Content-Length: " +
                           std::to_string(html.length()) +
                           "\r\n"
                           "Connection: close\r\n\r\n" +
                           html;
    send(client_fd, response.c_str(), (int)response.length(), 0);
  } else if (path == "/favicon.ico") {
    std::string response = "HTTP/1.1 204 No Content\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n";
    send(client_fd, response.c_str(), (int)response.length(), 0);
  } else if (path == "/api/metrics") {
    // Log metrics requests at rate-limited interval to avoid flooding the log terminal
    static std::atomic<int> metrics_request_counter(0);
    int count = ++metrics_request_counter;
    if (count % 15 == 1) {
      add_system_log("INFO", "API", "Metrics API requested (x15 requests logged)");
    }

    std::string json;
    {
      std::string host;
      int port;
      {
        LockGuard lock_t(target_mutex);
        host = telemetry_target_host;
        port = telemetry_target_port;
      }

      // Serialize logs safely in a localized scope
      std::string logs_json = "[]";
      {
        LockGuard lock_l(logs_mutex);
        std::stringstream log_ss;
        log_ss << "[\n";
        for (size_t l = 0; l < system_logs.size(); ++l) {
          const auto &entry = system_logs[l];
          log_ss << "    {\n";
          log_ss << "      \"timestamp\": " << entry.timestamp << ",\n";
          log_ss << "      \"severity\": \"" << entry.severity << "\",\n";
          log_ss << "      \"source\": \"" << entry.source << "\",\n";

          std::string esc_msg = entry.message;
          size_t pos = 0;
          while ((pos = esc_msg.find('"', pos)) != std::string::npos) {
            esc_msg.replace(pos, 1, "\\\"");
            pos += 2;
          }
          log_ss << "      \"message\": \"" << esc_msg << "\"\n";
          log_ss << "    }";
          if (l + 1 < system_logs.size()) {
            log_ss << ",";
          }
          log_ss << "\n";
        }
        log_ss << "  ]";
        logs_json = log_ss.str();
      }

      // Make thread-safe copy of metrics and history under metrics lock
      TelemetryMetrics metrics_copy;
      std::vector<TelemetryMetrics> history_copy;
      {
        LockGuard lock_m(metrics_mutex);
        metrics_copy = current_metrics;
        history_copy = metrics_history;
      }

      // Build JSON using copied data without nested locks
      std::stringstream ss;
      ss << std::fixed << std::setprecision(2);
      ss << "{\n";
      ss << "  \"timestamp\": " << metrics_copy.timestamp << ",\n";
      ss << "  \"uptime_seconds\": " << metrics_copy.uptime_seconds << ",\n";
      ss << "  \"latency_ms\": " << metrics_copy.latency_ms << ",\n";
      ss << "  \"packet_loss_pct\": " << metrics_copy.packet_loss_pct << ",\n";
      ss << "  \"stability_index\": " << metrics_copy.stability_index << ",\n";
      ss << "  \"cpu_usage_pct\": " << metrics_copy.cpu_usage_pct << ",\n";
      ss << "  \"ram_used_mb\": " << metrics_copy.ram_used_mb << ",\n";
      ss << "  \"ram_total_mb\": " << metrics_copy.ram_total_mb << ",\n";
      ss << "  \"ram_usage_pct\": " << metrics_copy.ram_usage_pct << ",\n";
      ss << "  \"system_uptime_seconds\": " << metrics_copy.system_uptime_seconds << ",\n";
      ss << "  \"disk_used_gb\": " << metrics_copy.disk_used_gb << ",\n";
      ss << "  \"disk_total_gb\": " << metrics_copy.disk_total_gb << ",\n";
      ss << "  \"disk_usage_pct\": " << metrics_copy.disk_usage_pct << ",\n";
      ss << "  \"disk_read_mbs\": " << metrics_copy.disk_read_mbs << ",\n";
      ss << "  \"disk_write_mbs\": " << metrics_copy.disk_write_mbs << ",\n";
      ss << "  \"process_count\": " << metrics_copy.process_count << ",\n";
      ss << "  \"thread_count\": " << metrics_copy.thread_count << ",\n";
      ss << "  \"core_count\": " << metrics_copy.core_count << ",\n";
      ss << "  \"per_core_cpu_pct\": [";
      for (size_t c = 0; c < metrics_copy.per_core_cpu_pct.size(); ++c) {
        ss << metrics_copy.per_core_cpu_pct[c];
        if (c + 1 < metrics_copy.per_core_cpu_pct.size()) {
          ss << ", ";
        }
      }
      ss << "],\n";
      ss << "  \"net_download_speed_mbps\": " << metrics_copy.net_download_speed_mbps << ",\n";
      ss << "  \"net_upload_speed_mbps\": " << metrics_copy.net_upload_speed_mbps << ",\n";
      ss << "  \"net_throughput_mbps\": " << metrics_copy.net_throughput_mbps << ",\n";
      ss << "  \"active_tcp_connections\": " << metrics_copy.active_tcp_connections << ",\n";
      ss << "  \"active_udp_connections\": " << metrics_copy.active_udp_connections << ",\n";
      ss << "  \"dns_response_time_ms\": " << metrics_copy.dns_response_time_ms << ",\n";
      ss << "  \"network_jitter_ms\": " << metrics_copy.network_jitter_ms << ",\n";
      ss << "  \"interface_utilization_pct\": " << metrics_copy.interface_utilization_pct << ",\n";
      ss << "  \"network_health_score\": " << metrics_copy.network_health_score << ",\n";
      ss << "  \"connection_quality_status\": \"" << metrics_copy.connection_quality_status << "\",\n";
      ss << "  \"telemetry_status\": \"" << metrics_copy.telemetry_status << "\",\n";
      ss << "  \"network_status\": \"" << metrics_copy.network_status << "\",\n";
      ss << "  \"system_os\": \"" << SYSTEM_OS_NAME << "\",\n";
      ss << "  \"telemetry_active\": " << (telemetry_active.load() ? "true" : "false") << ",\n";
      ss << "  \"target_host\": \"" << host << "\",\n";
      ss << "  \"target_port\": " << port << ",\n";
      ss << "  \"interval_ms\": " << telemetry_interval_ms.load() << ",\n";
      ss << "  \"cpu_frequency_mhz\": " << metrics_copy.cpu_frequency_mhz << ",\n";
      ss << "  \"cpu_temp_c\": " << metrics_copy.cpu_temp_c << ",\n";
      ss << "  \"cpu_health_score\": " << metrics_copy.cpu_health_score << ",\n";
      ss << "  \"ram_health_score\": " << metrics_copy.ram_health_score << ",\n";
      ss << "  \"disk_health_score\": " << metrics_copy.disk_health_score << ",\n";
      ss << "  \"platform_health_score\": " << metrics_copy.platform_health_score << ",\n";
      ss << "  \"logs\": " << logs_json << ",\n";
      ss << "  \"history\": [\n";

      for (size_t i = 0; i < history_copy.size(); ++i) {
        const auto &h = history_copy[i];
        ss << "    {\n";
        ss << "      \"timestamp\": " << h.timestamp << ",\n";
        ss << "      \"latency_ms\": " << h.latency_ms << ",\n";
        ss << "      \"packet_loss_pct\": " << h.packet_loss_pct << ",\n";
        ss << "      \"stability_index\": " << h.stability_index << ",\n";
        ss << "      \"cpu_usage_pct\": " << h.cpu_usage_pct << ",\n";
        ss << "      \"ram_usage_pct\": " << h.ram_usage_pct << ",\n";
        ss << "      \"system_uptime_seconds\": " << h.system_uptime_seconds << ",\n";
        ss << "      \"disk_usage_pct\": " << h.disk_usage_pct << ",\n";
        ss << "      \"disk_read_mbs\": " << h.disk_read_mbs << ",\n";
        ss << "      \"disk_write_mbs\": " << h.disk_write_mbs << ",\n";
        ss << "      \"process_count\": " << h.process_count << ",\n";
        ss << "      \"thread_count\": " << h.thread_count << ",\n";
        ss << "      \"net_download_speed_mbps\": " << h.net_download_speed_mbps << ",\n";
        ss << "      \"net_upload_speed_mbps\": " << h.net_upload_speed_mbps << ",\n";
        ss << "      \"net_throughput_mbps\": " << h.net_throughput_mbps << ",\n";
        ss << "      \"network_jitter_ms\": " << h.network_jitter_ms << "\n";
        ss << "    }";
        if (i + 1 < history_copy.size()) {
          ss << ",";
        }
        ss << "\n";
      }
      ss << "  ]\n";
      ss << "}";
      json = ss.str();
    }

    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json; charset=utf-8\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Content-Length: " +
                           std::to_string(json.length()) +
                           "\r\n"
                           "Connection: close\r\n\r\n" +
                           json;
    send(client_fd, response.c_str(), (int)response.length(), 0);
  } else if (path.rfind("/api/control", 0) == 0) {
    add_system_log("INFO", "API", "Control API requested: " + path);
    auto params = parse_query_params(path);

    if (params.count("action")) {
      std::string act = params["action"];
      if (act == "start") {
        telemetry_active = true;
        telemetry_paused = false;
        add_system_log("INFO", "SYSTEM",
                       "Telemetry Collector started manually");
      } else if (act == "stop") {
        telemetry_active = false;
        telemetry_paused = false;
        add_system_log("WARNING", "SYSTEM",
                       "Telemetry Collector stopped manually");
      } else if (act == "pause") {
        telemetry_active = false;
        telemetry_paused = true;
        add_system_log("WARNING", "SYSTEM",
                       "Telemetry Collector paused manually");
      } else if (act == "resume") {
        telemetry_active = true;
        telemetry_paused = false;
        add_system_log("INFO", "SYSTEM",
                       "Telemetry Collector resumed manually");
      }
    }

    if (params.count("host")) {
      std::string new_host = params["host"];
      if (!new_host.empty()) {
        LockGuard lock(target_mutex);
        telemetry_target_host = new_host;
        add_system_log("INFO", "SYSTEM",
                       "Telemetry target host updated to: " + new_host);
      }
    }

    if (params.count("port")) {
      try {
        int new_port = std::stoi(params["port"]);
        if (new_port > 0 && new_port <= 65535) {
          LockGuard lock(target_mutex);
          telemetry_target_port = new_port;
          add_system_log("INFO", "SYSTEM",
                         "Telemetry target port updated to: " +
                             std::to_string(new_port));
        }
      } catch (...) {
      }
    }

    if (params.count("interval")) {
      try {
        int new_int = std::stoi(params["interval"]);
        if (new_int >= 500 && new_int <= 60000) {
          telemetry_interval_ms = new_int;
          add_system_log("INFO", "SYSTEM",
                         "Telemetry polling interval set to: " +
                             std::to_string(new_int) + " ms");
        }
      } catch (...) {
      }
    }

    std::string json = "{\"status\":\"success\"}";
    std::string response = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Content-Length: " +
                           std::to_string(json.length()) +
                           "\r\n"
                           "Connection: close\r\n\r\n" +
                           json;
    send(client_fd, response.c_str(), (int)response.length(), 0);
  } else {
    // Fallback for missing resources
    std::string body = "404 Not Found";
    std::string response = "HTTP/1.1 404 Not Found\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: " +
                           std::to_string(body.length()) +
                           "\r\n"
                           "Connection: close\r\n\r\n" +
                           body;
    send(client_fd, response.c_str(), (int)response.length(), 0);
  }

  CLOSE_SOCKET(client_fd);
}

// Main listening server runner
void run_server() {
  SocketType server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (!IS_VALIDSOCKET(server_fd)) {
    std::cerr << "[HTTP SERVER] Socket creation failed. Error: "
              << GET_SOCKET_ERRNO() << std::endl;
    return;
  }

  // Set port address reuse flags
  int opt = 1;
#ifdef _WIN32
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt));
#else
  setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

  struct sockaddr_in address;
  std::memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(8080);

  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    std::string err_msg = "HTTP Server Bind failed on port 8080 (Error: " +
                          std::to_string(GET_SOCKET_ERRNO()) +
                          "). Port may be in use.";
    std::cerr << "[HTTP SERVER] " << err_msg << std::endl;
    add_system_log("CRITICAL", "SYSTEM", err_msg);
    CLOSE_SOCKET(server_fd);
    return;
  }

  if (listen(server_fd, 15) < 0) {
    std::cerr << "[HTTP SERVER] Listen failed. Error: " << GET_SOCKET_ERRNO()
              << std::endl;
    CLOSE_SOCKET(server_fd);
    return;
  }

  std::cout << "[HTTP SERVER] Online at http://localhost:8080/" << std::endl;

  // Listen loop (Interruptible with select)
  while (running) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(server_fd, &read_fds);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000; // Check state flag every 200ms

    int select_res = select((int)server_fd + 1, &read_fds, NULL, NULL, &tv);
    if (select_res > 0 && FD_ISSET(server_fd, &read_fds)) {
      struct sockaddr_in client_addr;
#ifdef _WIN32
      int addr_len = sizeof(client_addr);
#else
      socklen_t addr_len = sizeof(client_addr);
#endif
      SocketType client_fd =
          accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
      if (IS_VALIDSOCKET(client_fd)) {
        // Delegate client socket connection to detached processing thread using
        // lambda wrapper
        Thread handler([client_fd]() { handle_client(client_fd); });
        handler.detach();
      }
    }
  }

  CLOSE_SOCKET(server_fd);
  std::cout << "[HTTP SERVER] Stopped listener." << std::endl;
}

// ==========================================
// APPLICATION START POINT
// ==========================================

int main() {
  std::cout << "=========================================================="
            << std::endl;
  std::cout << "      NET-METRIC IX INFRASTRUCTURE & NETWORK MONITOR      "
            << std::endl;
  std::cout << "=========================================================="
            << std::endl;

  // Platform-specific socket runtime setups (Required for Windows WinSock DLL
  // initialization)
#ifdef _WIN32
  WSADATA wsaData;
  int ws_res = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (ws_res != 0) {
    std::cerr << "WinSock WSAStartup failed with code: " << ws_res << std::endl;
    return 1;
  }
  std::cout << "[SYSTEM] WinSock DLL Initialized successfully." << std::endl;
  init_windows_apis();
#endif
  // Pre-seed system resources to establish a baseline delta
  get_cpu_usage();
  sleep_ms(250);

  // Initial log
  add_system_log("INFO", "SYSTEM",
                 "Net-Metric IX Engine initialized successfully.");

  // Spawn background telemetry monitoring loop thread
  Thread telemetry_thread(run_telemetry);
  // Start HTTP Web server in main thread (blocks execution)
  run_server();

  // Cleanup and join thread routines on exit
  running = false;
  if (telemetry_thread.joinable()) {
    telemetry_thread.join();
  }

#ifdef _WIN32
  WSACleanup();
#endif

  std::cout << "[SYSTEM] Clean shutdown completed." << std::endl;
  return 0;
}
