// Source: OWASP Juice Shop (https://github.com/juice-shop/juice-shop)
// Commit: c50f4f9a03b6dc248d7c48f2fae3f167e45b46e8
// File: routes/userProfile.ts
// License: MIT
// Labelled: safe_control (CWE-89) by security-team at 2026-11-20

const express = require('express');
const router = express.Router();
const { Allocation, Op } = require('../models');

router.post('/allocations/safe-search', async (req, res) => {
  const asset = String(req.body.asset || '');
  // Safe: Sequelize structured query clause with built-in parameterization and escaping
  const results = await Allocation.findAll({
    where: {
      asset: {
        [Op.like]: `%${asset}%`
      }
    }
  });
  res.json(results);
});

module.exports = router;
