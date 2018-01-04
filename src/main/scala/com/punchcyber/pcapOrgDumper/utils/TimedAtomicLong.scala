package com.punchcyber.pcapOrgDumper.utils

import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

class TimedAtomicLong(num: Long) extends AtomicLong {
    var lastWrittenTo: Instant = Instant.now()
    
    def addSetAndGet(delta: Long): TimedAtomicLong = {
        this.addAndGet(delta)
        this.lastWrittenTo = Instant.now()
        this
    }
}
