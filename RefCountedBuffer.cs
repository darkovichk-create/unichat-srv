// Original UniChat server author: Sergey Rihmayer (s.rihmayer@mail.ru)

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace UniChatServerd
{
    internal class RefCountedBuffer
    {
        // private static long _created; // debug
        // private static long _disposed; // debug

        // public static long Alive => Interlocked.Read(ref _created) - Interlocked.Read(ref _disposed); // debug
        // public static long Created => Interlocked.Read(ref _created); // debug
        // public static long Disposed => Interlocked.Read(ref _disposed); // debug



        private readonly byte[] _array;
        private readonly int _length;
        private int _refs;

        public Memory<byte> Memory => _array.AsMemory(0, _length);

        public RefCountedBuffer(byte[] array, int length)
        {
            _array = array;
            _length = length;
            _refs = 1;

            // Interlocked.Increment(ref _created); // debug
        }

        public void AddRef() => Interlocked.Increment(ref _refs);

        public void Release()
        {
            if (Interlocked.Decrement(ref _refs) == 0)
            {
                // Interlocked.Increment(ref _disposed); // debug
                ArrayPool<byte>.Shared.Return(_array);
            }
        }
    }
}
