package com.boardend.boardend.models;

import java.util.List;

public class DeliveryResponse {
    private List<MobileDelivery> deliveries;
    private double totalAmount;


    public DeliveryResponse(List<MobileDelivery> deliveries, double totalAmount) {
        this.deliveries = deliveries;
        this.totalAmount = totalAmount;
    }

    public List<MobileDelivery> getDeliveries() {
        return deliveries;
    }

    public void setDeliveries(List<MobileDelivery> deliveries) {
        this.deliveries = deliveries;
    }

    public double getTotalAmount() {
        return totalAmount;
    }

    public void setTotalAmount(double totalAmount) {
        this.totalAmount = totalAmount;
    }
}