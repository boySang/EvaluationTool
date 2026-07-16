using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace AssessmentTool.Windows.Storage;

internal sealed class KeyedAsyncLock
{
    private readonly ConcurrentDictionary<string, Entry> entries;

    public KeyedAsyncLock(StringComparer comparer)
    {
        entries = new ConcurrentDictionary<string, Entry>(comparer ?? throw new ArgumentNullException(nameof(comparer)));
    }

    public int Count => entries.Count;

    public async Task<IDisposable> AcquireAsync(string key, CancellationToken cancellationToken)
    {
        if (key == null)
        {
            throw new ArgumentNullException(nameof(key));
        }

        Entry entry;
        while (true)
        {
            var candidate = new Entry();
            entry = entries.GetOrAdd(key, candidate);
            if (!ReferenceEquals(entry, candidate))
            {
                candidate.Dispose();
            }

            lock (entry.SyncRoot)
            {
                if (entry.IsRetired)
                {
                    continue;
                }

                entry.ReferenceCount++;
                break;
            }
        }

        try
        {
            await entry.Semaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            return new Lease(this, key, entry);
        }
        catch
        {
            ReleaseReference(key, entry);
            throw;
        }
    }

    private void ReleaseLease(string key, Entry entry)
    {
        entry.Semaphore.Release();
        ReleaseReference(key, entry);
    }

    private void ReleaseReference(string key, Entry entry)
    {
        var shouldDispose = false;
        lock (entry.SyncRoot)
        {
            entry.ReferenceCount--;
            if (entry.ReferenceCount < 0)
            {
                throw new InvalidOperationException("Keyed async lock reference count became negative.");
            }

            if (entry.ReferenceCount == 0)
            {
                entry.IsRetired = true;
                Entry removedEntry;
                if (!entries.TryRemove(key, out removedEntry) || !ReferenceEquals(entry, removedEntry))
                {
                    throw new InvalidOperationException("Keyed async lock entry could not be removed safely.");
                }

                shouldDispose = true;
            }
        }

        if (shouldDispose)
        {
            entry.Dispose();
        }
    }

    private sealed class Entry : IDisposable
    {
        public object SyncRoot { get; } = new object();
        public SemaphoreSlim Semaphore { get; } = new SemaphoreSlim(1, 1);
        public int ReferenceCount { get; set; }
        public bool IsRetired { get; set; }

        public void Dispose()
        {
            Semaphore.Dispose();
        }
    }

    private sealed class Lease : IDisposable
    {
        private KeyedAsyncLock? owner;
        private readonly string key;
        private readonly Entry entry;

        public Lease(KeyedAsyncLock owner, string key, Entry entry)
        {
            this.owner = owner;
            this.key = key;
            this.entry = entry;
        }

        public void Dispose()
        {
            var currentOwner = Interlocked.Exchange(ref owner, null);
            currentOwner?.ReleaseLease(key, entry);
        }
    }
}
