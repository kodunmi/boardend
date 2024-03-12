package com.boardend.boardend.repository;

import com.boardend.boardend.models.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface RiderRepository extends JpaRepository<Rider, Long> {
    List<Rider> findByAvailable(boolean available);

    Optional<Rider> findByUsername(String username);

    List<Rider> findByName(String name);

    Optional<Rider> findByUsernameIgnoreCase(String username);

    boolean existsByUsername(String username);

    Page<Rider> findByUser(User user, Pageable pageable);

    Optional<Rider> findByIdAndUser(Long id, User user);

    Optional<Rider> findByAvailableAndStatusIn(boolean available, List<DeliveryStatus> statuses);

    Optional<Rider> findById(Long id);

    @Query("SELECT COUNT(r) FROM Rider r WHERE r.user = :user")
    long countByUser(@Param("user") User user);

    // New methods to check if vehicle number and phone number already exist
    Optional<Rider> findByVehicleNumber(String vehicleNumber);

    Optional<Rider> findByPhone(String phone);

    Optional<Rider> findOneByUser(User user);

    @Query("SELECT r FROM Rider r WHERE r.user = :user")
    Optional<Rider> findByUserWithJsonIgnoreProperties(@Param("user") User user);

    boolean existsByVehicleNumber(String vehicleNumber);

    boolean existsByPhone(String phone);
}
