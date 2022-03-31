import time
import csv
import datetime
import psutil as ps

class cpulogs:
    time_today = str(datetime.datetime.now())

    with open('VM_INFO'+time_today+'.csv', 'a') as file:
        writer = csv.writer(file)
        writer.writerow(
            ['date','time','cpu_load', 'idle_time_cpu', 'kernal_process_time_cpu', 'normal_process_time_usermode_cpu', 'freq_max', 'freq_min',
             'disk_usage_total', 'disk_usage_used', 'disk_usage_free', 'disk_usage_in_percent', 'disk_reading_count',
             'disk_writing_count', 'disk_reading_bytes', 'disk_writing_bytes'])

        for i in range(90000000):
            date = time.strftime('%d-%m-%Y')
            now = time.strftime('%H:%M:%S')
            idle_time_cpu = ps.cpu_times().idle
            kernal_process_time_cpu = ps.cpu_times().system
            normal_process_time_usermode_cpu = ps.cpu_times().user
            # iowait_time_cpu = ps.cpu_times_percent().iowait
            freq_max = ps.cpu_freq().max
            freq_min = ps.cpu_freq().min
            disk_usage_total = ((ps.disk_usage('/').total) // (2 ** 30))
            disk_usage_used = ((ps.disk_usage('/').used) // (2 ** 30))
            disk_usage_free = ((ps.disk_usage('/').free) // (2 ** 30))
            disk_usage_in_percent = ps.disk_usage('/').percent
            disk_reading_count = ps.disk_io_counters(perdisk=False).read_count
            disk_writing_count = ps.disk_io_counters(perdisk=False).write_count
            disk_reading_bytes = ps.disk_io_counters(perdisk=False).read_bytes
            disk_writing_bytes = ps.disk_io_counters(perdisk=False).write_bytes

            cpu_load2 = ps.cpu_percent(1)
            cpu_load = float(cpu_load2)
            writer.writerow(
                [date,now, cpu_load, idle_time_cpu, kernal_process_time_cpu, normal_process_time_usermode_cpu, freq_max, freq_min,
                 disk_usage_total, disk_usage_used, disk_usage_free, disk_usage_in_percent, disk_reading_count,
                 disk_writing_count, disk_reading_bytes, disk_writing_bytes])

            print(date, now,cpu_load, disk_usage_used, kernal_process_time_cpu)
