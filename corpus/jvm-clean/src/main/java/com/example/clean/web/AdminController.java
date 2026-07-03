package com.example.clean.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * corpus: jvm-clean — admin order management, properly role-gated.
 * The destructive action requires the ADMIN role (not mere authentication).
 */
@RestController
@RequestMapping("/api/admin/orders")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {

    private final OrderRepository orders;

    public AdminController(OrderRepository orders) {
        this.orders = orders;
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public String delete(@PathVariable("id") Long id) {
        orders.deleteById(id);
        return "deleted " + id;
    }

    interface OrderRepository {
        void deleteById(Long id);
    }
}
