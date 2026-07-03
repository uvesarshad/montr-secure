package com.example.vuln.web;

import com.example.vuln.model.Order;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * corpus: jvm-vuln — admin order management. DO NOT DEPLOY.
 * Planted: A01:2021 Broken Access Control (authenticated but no role check).
 */
@RestController
@RequestMapping("/api/admin/orders")
@PreAuthorize("isAuthenticated()")
public class AdminController {

    private final OrderRepository orders;

    public AdminController(OrderRepository orders) {
        this.orders = orders;
    }

    // A01:2021 — Broken Access Control: the class only requires *authentication*
    // (isAuthenticated), never an ADMIN role, so any logged-in user can delete
    // any order by id. A privileged, destructive action with no authorization.
    @DeleteMapping("/{id}")
    public String delete(@PathVariable("id") Long id) {
        orders.deleteById(id);
        return "deleted " + id;
    }

    interface OrderRepository {
        void deleteById(Long id);

        List<Order> findAll();
    }
}
