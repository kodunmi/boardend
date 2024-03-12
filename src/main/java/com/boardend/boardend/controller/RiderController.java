package com.boardend.boardend.controller;

import com.boardend.boardend.models.Delivery;
import com.boardend.boardend.models.DeliveryStatus;
import com.boardend.boardend.models.MobileDelivery;
import com.boardend.boardend.models.PaymentType;
import com.boardend.boardend.models.Rider;
import com.boardend.boardend.models.User;
import com.boardend.boardend.payload.response.ApiResponse;
import com.boardend.boardend.repository.DeliveryRepository;
import com.boardend.boardend.repository.MobileDeliveryRepository;
import com.boardend.boardend.repository.MobileUserRepository;
import com.boardend.boardend.repository.RiderRepository;
import com.boardend.boardend.repository.UserRepository;
import com.boardend.boardend.security.services.RiderDetailsImpl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.data.util.Pair;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.context.SecurityContextHolder;

import java.security.Principal;
import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.time.temporal.TemporalAdjusters;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@CrossOrigin(origins = "https://dashboard.rubidelivery.com")
@RestController
@RequestMapping("/api/rider")
public class RiderController {

    Logger logger = LoggerFactory.getLogger(RiderController.class);

    @Autowired
    RiderRepository riderRepository;

    @Autowired
    UserRepository userRepository;

    @Autowired
    MobileDeliveryRepository mobileDeliveryRepository;

    @GetMapping("/rider")
    public ResponseEntity<List<Rider>> getAllRider(@RequestParam(required = false) String name) {
        try {
            List<Rider> riders = new ArrayList<Rider>();

            if (name == null)
                riderRepository.findAll().forEach(riders::add);
            else
                riderRepository.findByName(name).forEach(riders::add);

            if (riders.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.NO_CONTENT);
            }

            return new ResponseEntity<>(riders, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/rider/{id}")
    public ResponseEntity<Rider> getRiderById(@PathVariable("id") long id) {
        Optional<Rider> RiderData = riderRepository.findById(id);

        if (RiderData.isPresent()) {
            return new ResponseEntity<>(RiderData.get(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/earnings")
    public ResponseEntity<ApiResponse<Double>> getDriverEarnings(
            @RequestParam(required = false, defaultValue = "CASH") PaymentType type,
            @RequestParam(required = false, defaultValue = "WEEK") String date) {

        try {

            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            String riderUserName = authentication.getName();
            Rider rider = riderRepository.findByUsername(riderUserName).orElse(null);

            Pair<LocalDateTime, LocalDateTime> dateRange = getDateRange(date);

            LocalDateTime startDateTime = dateRange.getFirst();
            LocalDateTime endDateTime = dateRange.getSecond();

            List<MobileDelivery> relevantDeliveries = mobileDeliveryRepository
                    .findByRiderAndPaymentTypeAndStatusAndDeliveryTimeBetween(rider, type, DeliveryStatus.PICKED_UP,
                            startDateTime,
                            endDateTime);

            double totalEarnings = relevantDeliveries.stream()
                    .mapToDouble(MobileDelivery::getCommissionPayable)
                    .sum();

            ApiResponse<Double> response = new ApiResponse<>("Total earning fetched successfully", totalEarnings,
                    "success");
            return ResponseEntity.ok(response);

            // return new ResponseEntity<>(totalEarnings, HttpStatus.OK);

        } catch (Exception e) {
            return new ResponseEntity(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public static Pair<LocalDateTime, LocalDateTime> getDateRange(String type) {
        LocalDateTime now = LocalDateTime.now();

        switch (type.toUpperCase()) {
            case "TODAY":
                return Pair.of(LocalDateTime.of(now.toLocalDate(), LocalTime.MIN),
                        LocalDateTime.of(now.toLocalDate(), LocalTime.MAX));
            case "YESTERDAY":
                return Pair.of(LocalDateTime.of(now.toLocalDate().minusDays(1), LocalTime.MIN),
                        LocalDateTime.of(now.toLocalDate().minusDays(1), LocalTime.MAX));
            case "WEEK":
                return Pair.of(
                        LocalDateTime.of(now.toLocalDate().with(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY)),
                                LocalTime.MIN),
                        LocalDateTime.of(now.toLocalDate().with(TemporalAdjusters.nextOrSame(DayOfWeek.SUNDAY)),
                                LocalTime.MAX));
            case "MONTH":
                return Pair.of(
                        LocalDateTime.of(now.toLocalDate().with(TemporalAdjusters.firstDayOfMonth()), LocalTime.MIN),
                        LocalDateTime.of(now.toLocalDate().with(TemporalAdjusters.lastDayOfMonth()), LocalTime.MAX));
            case "YEAR":
                return Pair.of(
                        LocalDateTime.of(now.toLocalDate().with(TemporalAdjusters.firstDayOfYear()), LocalTime.MIN),
                        LocalDateTime.of(now.toLocalDate().with(TemporalAdjusters.lastDayOfYear()), LocalTime.MAX));
            default:
                throw new IllegalArgumentException("Invalid type provided");
        }
    }

    static class Pair<T, U> {
        private final T first;
        private final U second;

        private Pair(T first, U second) {
            this.first = first;
            this.second = second;
        }

        public static <T, U> Pair<T, U> of(T first, U second) {
            return new Pair<>(first, second);
        }

        public T getFirst() {
            return first;
        }

        public U getSecond() {
            return second;
        }

        @Override
        public String toString() {
            return "(" + first + ", " + second + ")";
        }
    }

    // @PostMapping("/rider")
    // public ResponseEntity<Rider> createRider(@RequestBody Rider rider) {
    // try {
    // Rider _rider = riderRepository
    // .save(new Rider(rider.getFirstName(), rider.getLastName(),
    // rider.getPhoneNumber(), rider.getStreetAddress(), rider.getEmail(),
    // false));
    // return new ResponseEntity<>(_rider, HttpStatus.CREATED);
    // } catch (Exception e) {
    // return new ResponseEntity<>(null, HttpStatus.INTERNAL_SERVER_ERROR);
    // }
    // }

    // @PutMapping("/rider/{id}")
    // public ResponseEntity<Rider> updateRider(@PathVariable("id") long id,
    // @RequestBody Rider rider) {
    // Optional<Rider> riderData = riderRepository.findById(id);
    //
    // if (riderData.isPresent()) {
    // Rider _rider = riderData.get();
    // _rider.setFirstName(rider.getFirstName());
    // _rider.setLastName(rider.getLastName());
    // _rider.setPhoneNumber(rider.getPhoneNumber());
    // _rider.setStreetAddress(rider.getStreetAddress());
    // _rider.setEmail(rider.getEmail());
    // _rider.setAvailable(rider.isAvailable());
    // return new ResponseEntity<>(riderRepository.save(_rider), HttpStatus.OK);
    // } else {
    // return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    // }
    // }

    @DeleteMapping("/rider/{id}")
    public ResponseEntity<HttpStatus> deleteRider(@PathVariable("id") long id) {
        try {
            riderRepository.deleteById(id);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @DeleteMapping("/rider")
    public ResponseEntity<HttpStatus> deleteAllRider() {
        try {
            riderRepository.deleteAll();
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/rider/available")
    public ResponseEntity<List<Rider>> findByAvailable() {
        try {
            List<Rider> rider = riderRepository.findByAvailable(true);

            if (rider.isEmpty()) {
                return new ResponseEntity<>(HttpStatus.NO_CONTENT);
            }
            return new ResponseEntity<>(rider, HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
