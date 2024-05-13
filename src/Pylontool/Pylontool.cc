/*
 * This is a camera duration test, it reports statistics at the end
 * part of: https://github.com/janwilmans/gvcp-tools
 */

#include <docopt.h>

#include <pylon/Device.h>
#include <pylon/Result.h>
#include <pylon/gige/BaslerGigECamera.h>

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <fmt/ostream.h>

#include <time.h>

#include <atomic>
#include <chrono>
#include <functional>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>

namespace config {

static int cameraWidth = 0;
static int cameraHeight = 0;
static int imageBufferSize = 0;
static constexpr int cameraBufferSize = 64;

} // namespace config

void setRegionOfInterest(int width, int height)
{
    config::cameraWidth = width;
    config::cameraHeight = height;
    config::imageBufferSize = width * height * 2;
}

using namespace std::chrono_literals;

struct AlreadyHandledException : std::exception
{
};

bool g_verbose = false;

template <>
struct fmt::formatter<Pylon::String_t> : public fmt::formatter<std::string>
{
    template <typename ParseContext>
    constexpr auto parse(ParseContext & ctx) { return fmt::formatter<std::string>::parse(ctx); }

    template <typename FormatContext>
    auto format(const Pylon::String_t & val, FormatContext & ctx)
    {
        return fmt::formatter<std::string>::format(val.c_str(), ctx);
    }
};

[[nodiscard]] std::string GetTimeStamp()
{
    timespec timespec;
    struct tm localTime;
    clock_gettime(CLOCK_REALTIME, &timespec);
    localtime_r(&(timespec.tv_sec), &localTime);
    return fmt::format("{:%Y-%m-%d %H:%M:%S}.{:03d}", localTime, timespec.tv_nsec / 1000000);
}

[[nodiscard]] uint64_t GetTimeStampMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// Prints the exception message, except if it is an 'already handled' exception (because then it was already printed)
void PrintExceptions(const char * function_name)
{
    try
    {
        throw;
    }
    catch (const GenICam::GenericException & e)
    {
        fmt::print("{} GenericException #1 '{}' in function '{}'\n", GetTimeStamp(), e.what(), function_name);
    }
    catch (const AlreadyHandledException &)
    {
        // do nothing
    }
    catch (const std::exception & e)
    {
        fmt::print("{} Exception '{}' in function '{}'\n", GetTimeStamp(), e.what(), function_name);
    }
    catch (...)
    {
        fmt::print("{} Exception '...' in function '{}'\n", GetTimeStamp(), function_name);
    }
}

void CheckedExecutionTime(std::string name, std::function<void()> func, int64_t timeout_ms = 200)
{
    const auto start = std::chrono::steady_clock::now();
    bool exception = true;
    try
    {
        func();
        exception = false;
    }
    catch (...)
    {
        PrintExceptions(__func__);
    }

    const auto end = std::chrono::steady_clock::now();
    const auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (diff > timeout_ms)
    {
        fmt::print("{} Timeout: function '{}' took {} ms\n", GetTimeStamp(), name, diff);
    }
    else if (g_verbose)
    {
        fmt::print("{} function '{}' took {} ms\n", GetTimeStamp(), name, diff);
    }

    if (exception)
    {
        throw AlreadyHandledException(); // make sure we exist the context of the exception, but not print/handle the same exception twice.
    }
}

class Camera
{
public:
    Camera(Pylon::CDeviceInfo * deviceInfo) :
        deviceInfo(deviceInfo)
    {
        transportLayer = Pylon::CTlFactory::GetInstance().CreateTl(Pylon::CBaslerGigECamera::DeviceClass());
    }

    Camera(const Camera &) = delete;
    Camera(Camera &&) = delete;
    Camera & operator=(const Camera &) = delete;
    Camera & operator==(Camera &&) = delete;

    [[nodiscard]] std::string GetSerialNumber()
    {
        return deviceInfo->GetSerialNumber().c_str();
    }

    [[nodiscard]] std::string GetContext()
    {
        return m_context;
    }

    [[nodiscard]] std::string GetDeviceVersion()
    {
        return deviceInfo->GetDeviceVersion().c_str();
    }

    [[nodiscard]] std::string GetFullName()
    {
        return deviceInfo->GetFullName().c_str();
    }

    void Open()
    {
        fmt::print("{} Open Camera\n Serial:{}\n  Device Version: {}\n  FullName: {}\n", GetTimeStamp(), GetSerialNumber(), GetDeviceVersion(), GetFullName());
        device = transportLayer->CreateDevice(*deviceInfo); // if this hangs check the cameras! a reboot may be needed!
        GigECamera = new Pylon::CBaslerGigECamera();
        if (!GigECamera->IsAttached() && device != nullptr)
        {
            GigECamera->Attach(device);
        }

        if (GigECamera->IsAttached())
        {
            CheckedExecutionTime(fmt::format("Open {}", GetSerialNumber()), [&] { GigECamera->Open(); });
        }
        auto firmware = std::string(GigECamera->DeviceFirmwareVersion.GetValue().c_str());
        m_context = fmt::format("{} with serial {}", firmware, GetSerialNumber());
        m_frequency = GigECamera->GevTimestampTickFrequency.GetValue(false, true);

        fmt::print("  Firmware Version: {}, Uptime: {}\n", firmware, std::chrono::duration_cast<std::chrono::seconds>(GetUptime()));

        CheckedExecutionTime(fmt::format("SetInitialParameters {}", GetContext()), [&] { SetInitialParameters(); });
        CheckedExecutionTime(fmt::format("SetupStreamGrabber {}", GetContext()), [&] { SetupStreamGrabber(); });
    }

    void Close()
    {
        int64_t retries = -1;
        try
        {
            Pylon::CPylonGigETLParams TlParams(GigECamera->GetTLNodeMap());
            retries = TlParams.StatisticReadWriteTimeoutCount.GetValue(false, true);
        }
        catch (const Pylon::GenericException & e)
        {
            fmt::print("Close stats GenericException ignored: {}.\n", e.what());
        }
        catch (const std::exception & e)
        {
            fmt::print("Close stats exception ignored: {}", e.what());
        }

        fmt::print("Close Camera {}, {} cycles, {} retries, exceptions: {}\n", GetContext(), m_cycleCount, retries, m_exceptionCount);

        try
        {
            if (callbackHandle)
            {
                GigECamera->DeregisterRemovalCallback(callbackHandle);
            }

            if (GigEStreamGrabber && GigEStreamGrabber->IsOpen())
            {
                GigEStreamGrabber->FinishGrab();
                GigEStreamGrabber->Close();
            }

            GigECamera->TriggerMode.SetValue(Basler_GigECamera::TriggerMode_Off);
            GigECamera->AcquisitionMode.SetValue(Basler_GigECamera::AcquisitionMode_Continuous);
        }
        catch (const Pylon::GenericException & e)
        {
            fmt::print("{}, DeregisterRemovalCallback, exception ignored: {}\n", GetContext(), e.what());
        }

        try
        {
            if (GigECamera)
            {
                GigECamera->Close();
                // delete GigECamera;
            }
        }
        catch (const Pylon::GenericException & e)
        {
            fmt::print("{}, Close, exception ignored: {}\n", GetContext(), e.what());
        }
    }

    void StopStartLoop(std::chrono::steady_clock::time_point end_time)
    {
        m_captureThread = std::thread([this, end_time] {
            while (std::chrono::steady_clock::now() < end_time)
            {
                CheckedExecutionTime(fmt::format("AcquisitionStop {}", GetContext()), [&] { GigECamera->AcquisitionStart.Execute(); });
                CheckedExecutionTime(fmt::format("AcquisitionStart {}", GetContext()), [&] { GigECamera->AcquisitionStart.Execute(); });
            } });
    }

    void StopStartLoopJoin()
    {
        m_captureThread.join();
    }

    void oneCapture()
    {
        try
        {
            CheckedExecutionTime(fmt::format("SetParameters {}", GetContext()), [&] { SetParameters(); });
            CheckedExecutionTime(fmt::format("Capture {}", GetContext()), [&] { Capture(); });
            LogStatistics();
        }
        catch (...)
        {
            m_exceptionCount++;
            LogStatistics();
            throw;
        }
    }

    void WaitUntilEndOfCapturing()
    {
        if (m_captureThread.joinable())
        {
            m_captureThread.join();
        }
    }

    void Reconnect()
    {
        Close();
        std::this_thread::sleep_for(1s);

        try
        {
            Open();
        }
        catch (const Pylon::GenericException & e)
        {
            fmt::print("Reconnect-Open GenericException ignored: {}.\n", e.what());
            return;
        }
        catch (const std::exception & e)
        {
            fmt::print("Reconnect-Open exception ignored: {}", e.what());
            return;
        }
    }

    // start a thread for every capture and return immediately
    void CaptureInBackground(std::chrono::steady_clock::time_point end_time)
    {
        m_captureThread = std::thread([this, end_time] {
            try
            {
                while (std::chrono::steady_clock::now() < end_time)
                {
                    bool exception = true;
                    try
                    {
                        oneCapture();
                        exception = false;
                        ++m_cycleCount;
                    }
                    catch (const Pylon::GenericException & e)
                    {
                        fmt::print("oneCapture GenericException ignored: {}.\n", e.what());
                    }
                    catch (const std::exception & e)
                    {
                        fmt::print("oneCapture exception ignored: {}", e.what());
                    }

                    if (exception)
                    {
                        Reconnect();
                    }
                }
                Close();
            }
            catch (...)
            {
                fmt::print(stderr, "unexpected ... exception!\n");
            } });
    }

    static const auto one_minute_ms = 60 * 1000;
    static const auto one_hours_ms = 60 * one_minute_ms;

    std::string GetAverages(uint64_t eventCount, uint64_t elapsedMs)
    {
        if (eventCount == 0)
        {
            return {};
        }
        const auto averageTimeBetweenEvents = elapsedMs / eventCount;
        const auto events_per_hour = one_hours_ms / averageTimeBetweenEvents;
        return fmt::format("({}/hour, ~ every {} minutes )", events_per_hour, averageTimeBetweenEvents / one_minute_ms);
    }

    void DeviceReset()
    {
        GigECamera->DeviceReset.Execute();
    }

    /*
        The valid values for 'GevCurrentIPConfiguration' are poorly documented, but from
        packet inspection we see that the pylon5 IpConfiguration tool sets only one 'bit' active at one time.

        VCenter however, sets the value to 7, which is odd but, maybe it was valid in the past?
        One possible meaning of '7' could be: try DHCP, fallback to LLA and persist address once received.
        However this was never found in official documentation

        // VCenter sets the value 7
        4 == LLA
        2 == DHCP
        1 == Persistent IP / Static IP
    */
    void SetToLLA()
    {
        auto previous = GigECamera->GevCurrentIPConfiguration.GetValue(false, true);
        // GigECamera->GevSupportedIPConfigurationPersistentIP.SetValue(false);
        // GigECamera->GevSupportedIPConfigurationDHCP.SetValue(false);
        // GigECamera->GevSupportedIPConfigurationLLA.SetValue(true);
        GigECamera->GevCurrentIPConfiguration = 4;
        fmt::print("Changed GevCurrentIPConfiguration from {} to {}\n", previous, GigECamera->GevCurrentIPConfiguration.GetValue(false, true));
    }

    void SetToLLAPersist()
    {
        auto previous = GigECamera->GevCurrentIPConfiguration.GetValue(false, true);
        GigECamera->GevCurrentIPConfiguration = 5;
        fmt::print("Changed GevCurrentIPConfiguration from {} to {}\n", previous, GigECamera->GevCurrentIPConfiguration.GetValue(false, true));
    }

    void SetToDHCP()
    {
        auto previous = GigECamera->GevCurrentIPConfiguration.GetValue(false, true);
        // GigECamera->GevSupportedIPConfigurationPersistentIP.SetValue(false);
        // GigECamera->GevSupportedIPConfigurationLLA.SetValue(false);
        // GigECamera->GevSupportedIPConfigurationDHCP.SetValue(true);
        GigECamera->GevCurrentIPConfiguration = 2;
        fmt::print("Changed GevCurrentIPConfiguration from {} to {}\n", previous, GigECamera->GevCurrentIPConfiguration.GetValue(false, true));
    }

    std::chrono::nanoseconds GetUptime()
    {
        auto nanoseconds_per_second = 1000000000;
        auto nanoseconds_per_tick = nanoseconds_per_second / m_frequency;

        GigECamera->GevTimestampControlLatch.Execute();
        auto timestamp = GigECamera->GevTimestampValue.GetValue();
        return std::chrono::nanoseconds(timestamp * nanoseconds_per_tick);
    }

    void TimestampControlReset()
    {
        GigECamera->GevTimestampControlReset.Execute();
    }

    void Log(std::string_view text)
    {
        fmt::print("{} {} {}\n", GetTimeStamp(), GetContext(), text);
    }

    void LogStatistics()
    {
        try
        {
            Pylon::CPylonGigETLParams TlParams(GigECamera->GetTLNodeMap());
            auto retries = TlParams.StatisticReadWriteTimeoutCount.GetValue(false, true);
            if (m_sendReplyRetryCount != retries)
            {
                m_sendReplyRetryCount = retries;
                auto now = GetTimeStampMs();
                auto elapsedMs = now - m_openTimestamp;
                auto averages = GetAverages(retries, elapsedMs);
                const auto timeSinceLastRetry = now - m_lastRetryTimestamp;
                m_lastRetryTimestamp = now;
                if (retries > 0)
                {
                    averages += fmt::format(", {} minutes since last retry", timeSinceLastRetry / one_minute_ms);
                }
                Log(fmt::format("Read/Write {} retries in {} minutes, {}", retries, elapsedMs / one_minute_ms, averages));
            }

            const auto bufferUnderrunCount = GigEStreamGrabber->Statistic_Buffer_Underrun_Count.GetValue();
            if (bufferUnderrunCount != m_bufferUnderrunCount)
            {
                Log(fmt::format("Buffer underrun count {}\n", bufferUnderrunCount));
                m_bufferUnderrunCount = bufferUnderrunCount;
            }
            const auto failedBufferCount = GigEStreamGrabber->Statistic_Failed_Buffer_Count.GetValue();
            if (failedBufferCount != m_failedBufferCount)
            {
                Log(fmt::format("Failed buffer count {}\n", failedBufferCount));
                m_failedBufferCount = failedBufferCount;
            }
            const auto failedPacketCount = GigEStreamGrabber->Statistic_Failed_Packet_Count.GetValue();
            if (failedPacketCount != m_failedPacketCount)
            {
                Log(fmt::format("Failed packet count {}\n", failedPacketCount));
                m_failedPacketCount = failedPacketCount;
            }
            const auto resendPacketCount = GigEStreamGrabber->Statistic_Resend_Packet_Count.GetValue();
            if (resendPacketCount != m_resendPacketCount)
            {
                Log(fmt::format("Resend packet count {}\n", resendPacketCount));
                m_resendPacketCount = resendPacketCount;
            }

            const auto resendRequestCount = GigEStreamGrabber->Statistic_Resend_Request_Count.GetValue();
            if (resendRequestCount != m_resendRequestCount)
            {
                Log(fmt::format("Resend request count {}\n", resendRequestCount));
                m_resendRequestCount = resendRequestCount;
            }
        }
        catch (const Pylon::GenericException & e)
        {
            fmt::print("LogStatistics GenericException ignored: {}.\n", e.what());
        }
        catch (const std::exception & e)
        {
            fmt::print("LogStatistics exception ignored: {}", e.what());
        }
        catch (...)
        {
            fmt::print("LogStatistics exception ignored.");
        }
    }

    void Capture()
    {
        struct CameraBuffer
        {
            Pylon::StreamBufferHandle handle{};
            std::vector<std::uint8_t> data;
        };
        std::vector<CameraBuffer> cameraBuffers(config::cameraBufferSize);

        for (auto & cameraBuffer : cameraBuffers)
        {
            cameraBuffer.data.resize(config::imageBufferSize);
            cameraBuffer.handle = GigEStreamGrabber->RegisterBuffer(cameraBuffer.data.data(), cameraBuffer.data.size());
            GigEStreamGrabber->QueueBuffer(cameraBuffer.handle);
        }

        CheckedExecutionTime(fmt::format("GevTimestampControlReset {}", GetContext()), [&] { GigECamera->GevTimestampControlReset.Execute(); });
        CheckedExecutionTime(fmt::format("AcquisitionStart {}", GetContext()), [&] { GigECamera->AcquisitionStart.Execute(); });
        CheckedExecutionTime(fmt::format("TriggerSoftware {}", GetContext()), [&] { GigECamera->TriggerSoftware.Execute(); });

        // throw RUNTIME_EXCEPTION(" TEST !"); // only for testing how exceptions are handled.

        const int waitTimeout = 2000; // milliseconds
        if (GigEStreamGrabber->GetWaitObject().Wait(waitTimeout))
        {
            Pylon::GrabResult result;
            if (GigEStreamGrabber->RetrieveResult(result))
            {
                if (g_verbose)
                {
                    fmt::print("GigEStreamGrabber->RetrieveResult GOOD!\n");

                    if (result.Succeeded())
                    {
                        fmt::print("Image Width = {} Height = {} \n", result.GetImage().GetWidth(), result.GetImage().GetHeight());
                    }
                    else
                    {
                        fmt::print("result.Succeeded() failed!, {}\n", result.GetErrorDescription());
                    }
                }

                using namespace std::chrono_literals;
                // acquireImageHandler(result); emulate copy
                std::this_thread::sleep_for(10ms);

                GigEStreamGrabber->QueueBuffer(result.Handle());
            }
            else
            {
                fmt::print("GigEStreamGrabber->RetrieveResult failed!\n");
            }
        }

        CheckedExecutionTime(fmt::format("AcquisitionStop {}", GetContext()), [&] { GigECamera->AcquisitionStop.Execute(); });
        // Flush the input queue, grabbing may have failed
        CheckedExecutionTime(fmt::format("CancelGrab {}", GetContext()), [&] { GigEStreamGrabber->CancelGrab(); });

        // Consume all items from the output queue
        while (GigEStreamGrabber->GetWaitObject().Wait(0))
        {
            Pylon::GrabResult Result;
            GigEStreamGrabber->RetrieveResult(Result);
        }

        for (auto & cameraBuffer : cameraBuffers)
        {
            if (cameraBuffer.handle)
            {
                GigEStreamGrabber->DeregisterBuffer(cameraBuffer.handle);
                cameraBuffer.handle = nullptr;
            }
        }
    }

    void SetParameters()
    {
        if (IsWritable(GigECamera->BinningHorizontal))
        {
            GigECamera->BinningHorizontal = 1;
        }

        if (IsWritable(GigECamera->BinningVertical))
        {
            GigECamera->BinningVertical = 1;
        }
    }

private:
    void SetInitialParameters()
    {
        Pylon::CPylonGigETLParams TlParams(GigECamera->GetTLNodeMap());
        TlParams.HeartbeatTimeout.SetValue(1000);
        //        TlParams.ReadTimeout.SetValue(500); // normal
        //        TlParams.WriteTimeout.SetValue(10); // very short
        callbackHandle = RegisterRemovalCallback(device, [](Pylon::IPylonDevice *) {});

        if (IsWritable(GigECamera->LineSelector))
        {
            GigECamera->LineSelector.SetValue(Basler_GigECamera::LineSelector_Out1);
        }

        if (IsWritable(GigECamera->LineSource))
        {
            GigECamera->LineSource.SetValue(Basler_GigECamera::LineSource_ExposureActive);
        }

        // this throws an exception on some cameras?
        // GigECamera->GevCurrentIPConfiguration = 7; // deprecated

        GigECamera->TriggerSelector.SetValue(Basler_GigECamera::TriggerSelector_FrameStart);
        GigECamera->TriggerMode.SetValue(Basler_GigECamera::TriggerMode_On);
        GigECamera->TriggerSource.SetValue(Basler_GigECamera::TriggerSource_Software);
        GigECamera->AcquisitionMode.SetValue(Basler_GigECamera::AcquisitionMode_SingleFrame);

        if (IsWritable(GigECamera->SequenceEnable))
        {
            GigECamera->SequenceEnable.SetValue(false);
        }

        if (IsWritable(GigECamera->SequenceAdvanceMode))
        {
            GigECamera->SequenceAdvanceMode.SetValue(Basler_GigECamera::SequenceAdvanceMode_Auto); // only supported mode for version 3.2.1
        }

        if (IsWritable(GigECamera->SequenceSetTotalNumber))
        {
            GigECamera->SequenceSetTotalNumber.SetValue(1);
        }

        if (IsWritable(GigECamera->GevSCPSPacketSize))
        {
            GigECamera->GevSCPSPacketSize.SetValue(8164);
        }

        if (IsWritable(GigECamera->GevSCPD))
        {
            GigECamera->GevSCPD.SetValue(12000); // 12000 for 2 cameras sharing the bandwidth
        }

        GigECamera->OffsetX.SetValue(0);
        GigECamera->OffsetY.SetValue(0);
        GigECamera->Width.SetValue(config::cameraWidth);
        GigECamera->Height.SetValue(config::cameraWidth);
        fmt::print("Set ROI: {},{} Size: {}, {}\n", GigECamera->OffsetX.GetValue(), GigECamera->OffsetY.GetValue(), GigECamera->Width.GetValue(), GigECamera->Height.GetValue());
    }

    void SetupStreamGrabber()
    {
        try
        {
            GigEStreamGrabber = new Pylon::CPylonGigEStreamGrabber();
            auto * pGrabber = GigECamera->GetStreamGrabber(0);
            GigEStreamGrabber->Attach(pGrabber);
            GigEStreamGrabber->Open();
            GigEStreamGrabber->MaxBufferSize.SetValue(config::cameraWidth * config::cameraHeight * 2);
            GigEStreamGrabber->MaxNumBuffer.SetValue(config::cameraBufferSize);
            GigEStreamGrabber->PrepareGrab();
        }
        catch (const GenICam::GenericException & e)
        {
            std::cout << "Failed to setup stream grabber " << m_context << e.what();
        }
    }

    std::thread m_captureThread;
    std::string m_serialNumber;
    std::string m_context;
    int64_t m_frequency;

    Pylon::ITransportLayer * transportLayer;
    Pylon::CDeviceInfo * deviceInfo;
    Pylon::IPylonDevice * device = nullptr;
    Pylon::CBaslerGigECamera * GigECamera = nullptr;
    Pylon::CPylonGigEStreamGrabber * GigEStreamGrabber = nullptr;
    Pylon::DeviceCallbackHandle callbackHandle = nullptr;

    uint64_t m_lastRetryTimestamp = GetTimeStampMs();
    uint64_t m_openTimestamp = GetTimeStampMs();

    // statistics
    int64_t m_bufferUnderrunCount{};
    int64_t m_failedBufferCount{};
    int64_t m_failedPacketCount{};
    int64_t m_resendPacketCount{};
    int64_t m_resendRequestCount{};
    int64_t m_sendReplyRetryCount = -1;
    int64_t m_exceptionCount = 0;
    int64_t m_cycleCount = 0;
};

class CameraDiscoverer
{
public:
    void Discover()
    {
        auto & factory = Pylon::CTlFactory::GetInstance();
        if (factory.EnumerateDevices(m_deviceInfoList) == 0)
        {
            throw RUNTIME_EXCEPTION(" No Basler cameras found");
        }

        for (auto & deviceInfo : m_deviceInfoList)
        {
            if (deviceInfo.GetDeviceClass() == Pylon::BaslerGigEDeviceClass)
            {
                std::cout << deviceInfo.GetFriendlyName() << std::endl;
                m_cameras.emplace_back(std::make_unique<Camera>(&deviceInfo));
            }
        }
    }

    [[nodiscard]] const std::vector<std::unique_ptr<Camera>> & GetCameras() const
    {
        return m_cameras;
    }

    [[nodiscard]] std::vector<std::unique_ptr<Camera>> & GetCamerasModifiable()
    {
        return m_cameras;
    }

private:
    Pylon::DeviceInfoList_t m_deviceInfoList;
    std::vector<std::unique_ptr<Camera>> m_cameras;
};

void CaptureAsVCenterWouldDoIt(const std::vector<std::unique_ptr<Camera>> & cameras, std::chrono::steady_clock::time_point end_time)
{
    for (const auto & camera : cameras)
    {
        camera->Open();
    }

    for (const auto & camera : cameras)
    {
        camera->CaptureInBackground(end_time); // create a new thread and
    }
    for (const auto & camera : cameras)
    {
        camera->WaitUntilEndOfCapturing();
    }
}

void StopStartLoop(const std::vector<std::unique_ptr<Camera>> & cameras, std::chrono::steady_clock::time_point end_time)
{
    fmt::print("Running StopAcquisition/StartAcquisition\n");
    for (const auto & camera : cameras)
    {
        camera->Open();
    }
    for (const auto & camera : cameras)
    {
        camera->StopStartLoop(end_time);
    }

    for (const auto & camera : cameras)
    {
        camera->StopStartLoopJoin();
    }

    for (const auto & camera : cameras)
    {
        camera->Close();
    }
}

void Close(const std::vector<std::unique_ptr<Camera>> & cameras)
{
    for (const auto & camera : cameras)
    {
        camera->Close();
    }
}

int asInt(const docopt::Options args, const std::string & name, int default_value)
{
    auto arg = args.at(name);
    if (!arg)
    {
        return default_value;
    }
    return static_cast<int>(arg.asLong());
}

bool asBool(const docopt::Options args, const std::string & name)
{
    auto arg = args.at(name);
    return arg && arg.asBool();
}

static constexpr const char * usage = R"(PylonTool

Usage:
  PylonTool [--verbose] [--duration=<minutes>] [--test=<number>] [--size=<number>] [--help]

Options:
  -v, --verbose             Show more information.
  -d --duration=<minutes>   Run test for specified amount of time [default: 30].
  -t --test=<number>        Run test number [default: 0].
  -s --size=<number>        Set Region of interest aka. image size, always square 0,0 and NxN [default: 400].
  -h --help                 Help (this text)

Tests:
  0 = Information info
  1 = capture as vcenter would
  2 = StopStartAcquisition loop
  3 = Reset cameras
  4 = Set cameras to LLA mode
  5 = Set cameras to LLA+persist mode (experimental, not recommended)
  6 = Set cameras to DHCP mode
  7 = TimestampControlReset cameras
)";

int main(int argc, char * argv[])
{
    try
    {
        const auto args = docopt::docopt(usage, {argv + 1, argv + argc}, true, "1.0");

        g_verbose = asBool(args, "--verbose");
        const int duration_minutes = asInt(args, "--duration", 30);
        const int test_number = asInt(args, "--test", 0);
        const int size = asInt(args, "--size", 0);
        const auto duration = std::chrono::minutes(duration_minutes);

        const auto start_time = std::chrono::steady_clock::now();
        if (duration_minutes == 0)
        {
            fmt::print("Running test {} endlessly.\n", test_number);
        }
        else
        {
            fmt::print("Running test {} for {}\n", test_number, duration);
        }

        const auto end_time = start_time + duration;
        setRegionOfInterest(size, size);

        Pylon::PylonAutoInitTerm initializePylon;
        auto cameraDiscoverer = CameraDiscoverer();
        cameraDiscoverer.Discover();
        const auto & cameras = cameraDiscoverer.GetCameras();
        fmt::print("Found {} cameras.\n\n", cameras.size());

        if (test_number == 1)
        {
            fmt::print("Running as-vcenter-would, starting new thread for every capture\n");
            CaptureAsVCenterWouldDoIt(cameras, end_time);
        }

        if (test_number == 2)
        {
            StopStartLoop(cameras, end_time);
        }

        if (test_number == 3)
        {
            for (auto & camera : cameraDiscoverer.GetCamerasModifiable())
            {
                camera->Open();
                fmt::print("Resetting {}.\n", camera->GetContext());
                camera->DeviceReset();
                camera.release();
            }
        }
        if (test_number == 4)
        {
            for (auto & camera : cameras)
            {
                camera->Open();
            }

            for (auto & camera : cameras)
            {
                fmt::print("Set GevCurrentIPConfiguration = 4 (LLA) for {}.\n", camera->GetContext());
                camera->SetToLLA();
            }
        }
        if (test_number == 5)
        {
            for (auto & camera : cameras)
            {
                camera->Open();
            }
            for (auto & camera : cameras)
            {
                fmt::print("Set GevCurrentIPConfiguration = 5 (LLA + persistence) for {}.\n", camera->GetContext());
                camera->SetToLLAPersist();
            }
        }

        if (test_number == 6)
        {
            for (auto & camera : cameras)
            {
                camera->Open();
            }
            for (auto & camera : cameras)
            {
                fmt::print("Set GevCurrentIPConfiguration = 2 (DHCP) for {}.\n", camera->GetContext());
                camera->SetToDHCP();
            }
        }

        if (test_number == 7)
        {
            fmt::print("TimestampControlReset Cameras...\n");
            for (auto & camera : cameras)
            {
                camera->Open();
            }
            for (auto & camera : cameras)
            {
                camera->TimestampControlReset();
            }
        }

        auto elapsed = std::chrono::steady_clock::now() - start_time;
        fmt::print("Finished after {}\n", std::chrono::duration_cast<std::chrono::seconds>(elapsed));
    }
    catch (...)
    {
        PrintExceptions(__func__);
    }

    return 0;
}
