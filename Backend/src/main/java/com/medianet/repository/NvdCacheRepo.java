package com.medianet.repository;

import com.medianet.entity.NvdCacheEntry;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NvdCacheRepo extends JpaRepository<NvdCacheEntry, String> {
}
