import resource
from collections import defaultdict

# Reload all custom modules
import cfi_util
reload(cfi_util)
import cfi_globals
reload(cfi_globals)

def print_max_mem_usage():
    cfi_globals.pyrebox_print('Max memory usage: %f GB' % (resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0 / 1024,))

def do_stats(line):
    import cfi
    pyrebox_print = cfi_globals.pyrebox_print
    d = cfi_globals.disassembler

    if d == None:
        pyrebox_print('Not initialized yet, waiting for %s to start' % cfi_globals.MONITORED_PROC_NAME)
        print_max_mem_usage()
        return

    pyrebox_print('Stats for %s:' % d.proc_name)
    pyrebox_print('--- Disassembler ---')
    d.print_stats()

    pyrebox_print('')
    pyrebox_print('--- Memory ---')
    pyrebox_print('Time spent caching memory: %ss (%d times)' % (cfi.tlb_exec_timer, cfi.tlb_exec_counter))
    cached_pages = len([a for a in d.memory.values() if a])
    pyrebox_print('Cached %d memory pages: %f MB' % (cached_pages, cached_pages * cfi.PAGE_SIZE / (1024.0 * 1024.0)))
    print_max_mem_usage()

    pyrebox_print('')
    pyrebox_print('--- CFI ---')
    pyrebox_print('Performed check results:')
    trigger_stats_max = 5
    trigger_stats = [d.get_stat(idx) for idx in range(0, trigger_stats_max)]
    trigger_stats_labels = ['Different process', 'Different privilege level', None, None, 'Valid control flow target']
    for i in range(0, trigger_stats_max):
        if trigger_stats_labels[i]:
            pyrebox_print('  %s: %d' % (trigger_stats_labels[i], trigger_stats[i]))

    if cfi_globals.DEBUG_OUTPUT:
        pyrebox_print('  trigger_stats: %s' % trigger_stats)

    pyrebox_print('  Control flow error: %d (unique: %d)' % (cfi.cfi_error_cnt,  len(cfi.cfi_errors)))

    # Print detailed information about errors
    if len(cfi.cfi_errors):
        # Some sanity checks
        for addr in cfi.cfi_errors:
            if addr in d.bb_start_offsets:
                pyrebox_print('Fatal error: Address %x is marked as valid control flow target but was reported as invalid' % addr)

            if addr in d.processed_offsets:
                pyrebox_print('Fatal error: Address %x was disassembled but not marked as valid control flow target' % addr)

        # Find corresponding modules to error addresses
        hits = defaultdict(list)
        for addr in cfi.cfi_errors:
            found = False
            for module in cfi_util.modules:
                if addr >= module['base'] and addr < module['base'] + module['size']:
                    found = True
                    hits[module['name']].append(addr)

            if not found:
                hits['No module'].append(addr)

        pyrebox_print('Control flow error targets')
        for name, hits in hits.iteritems():
            pyrebox_print('  %s: %d - %s' % (name, len(hits), ' '.join([hex(hit) for hit in hits])))

def do_monitor(line):
    if cfi_globals.disassembler:
        cfi_globals.pyrebox_print('Error: Monitoring already started, use reload_module to restart script')
        return

    old_monitored_proc = cfi_globals.MONITORED_PROC_NAME
    cfi_globals.MONITORED_PROC_NAME = line
    cfi_globals.MONITOR_KERNEL = cfi_globals.MONITORED_PROC_NAME == 'System'
    cfi_globals.pyrebox_print('Changed target to %s from %s' % (cfi_globals.MONITORED_PROC_NAME, old_monitored_proc))

    # Re-initialize monitoring
    from cfi import initialize_monitoring
    if old_monitored_proc:
        cfi_globals.cm.rm_callback('on_ep_' + old_monitored_proc)

    initialize_monitoring()

def do_monitor_kernel(line):
    do_monitor('System')

def do_strategy(line):
    error_strategies = ['log', 'dump', 'shell']
    if line not in error_strategies:
        cfi_globals.pyrebox_print('Error: invalid error handling strategy, use one of %s' % error_strategies)
    else:
        cfi_globals.ERROR_STRATEGY = line
        cfi_globals.pyrebox_print('Changed error handling strategy to: %s' % cfi_globals.ERROR_STRATEGY)

def do_settings(line):
    cfi_globals.pyrebox_print('Monitored process name: %s' % cfi_globals.MONITORED_PROC_NAME)
    cfi_globals.pyrebox_print('Error handling strategy: %s' % cfi_globals.ERROR_STRATEGY)

def do_set_guest_dump_path(line):
    cfi_globals.GUEST_DUMP_PATH = line
    cfi_globals.pyrebox_print('Changed guest dump path to: %s' % cfi_globals.GUEST_DUMP_PATH)










